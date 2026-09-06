import base64
from typing import Any, Self

import pydantic_core
from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from lxml import etree
from as4.core.common import (
    AS4BaseCredentials,
    AS4ExternalParty,
    AS4PartyIdentity,
    index_elements_by_id,
)
from as4.core.serialisation import SerialisableBytes, SerialisableCertificate, SerialisableParseError
from as4.core.context import AS4ParseContext, SecurityPolicy
from as4.errors import (
    BaseAS4ReceiptableError,
    CipherValueNotFoundException,
    DecryptionFailedException,
    DigestMismatchException,
    EncryptionRequiredException,
    MalformedSoapEnvelopeException,
    SignatureRequiredException,
    ReferenceTargetNotFoundException,
    CipherReferenceNotFoundException,
    EncryptedAttachmentNotFoundException,
    EncryptedDataNotFoundException,
    EncryptedDataReferenceNotFoundException,
    MessageIdNotFoundException,
    MessagingNotFoundException,
    PartInfoWithoutMimePartException,
    PayloadInfoNotFoundException,
    PartyToNotFoundException,
    SignatureSecurityTokenReferenceNotFoundException,
    SignatureCoverageException,
    SignatureVerificationFailedException,
    RemotePartyNotVerifiedError,
    UnsupportedDigestAlgorithmException,
    UnsupportedEncryptionAlgorithmException,
    UnsupportedSecurityTokenTypeException,
    UnsupportedSignatureAlgorithmException,
    UnsupportedTransformException,
    UntrustedSignerError,
    UntrustedSignerException,
    UserMessageNotFoundException,
)
from as4.models.common import NAMESPACES
from as4.models.dsig.reference import ComparableReferenceFields
from as4.models.dsig.reference import Reference as DsigReference
from as4.models.dsig.reference import UnsupportedDigestAlgorithm, UnsupportedTransform
from as4.models.dsig.signature import Signature, UnsupportedSignatureAlgorithm
from as4.models.soap.envelope import Envelope
from as4.models.ebms.user_message import PartyFrom, PartyTo
from as4.models.wsse.binary_security_token import UnsupportedSecurityTokenType
from as4.models.wsse.security import Security
from as4.models.xenc.encrypted_type import EncryptionAlgorithm
from as4.utils.mime_handler import MIMEHandler
from as4.utils.xml_parser import parse_xml
from pydantic import BaseModel, ConfigDict, Field


PARTY_TO_PATH = "./S12:Header/eb3:Messaging/eb3:UserMessage/eb3:PartyInfo/eb3:To"

COVERAGE_BY_TAG = {
    "{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Messaging": "messaging",
    "{http://www.w3.org/2003/05/soap-envelope}Body": "body",
}


class AS4Message(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    soap_envelope: Envelope | None = None
    mime_attachments: dict[str, SerialisableBytes] = Field(default_factory=dict)
    decrypted_data: dict[str, SerialisableBytes] = Field(default_factory=dict)
    profile_name: str | None = None

    message_id: str = ""
    messaging_id: str = ""
    addressed_to: AS4PartyIdentity | None = None
    signer_certificate: SerialisableCertificate | None = None
    parse_error: SerialisableParseError | None = None

    @property
    def parse_successful(self) -> bool:
        return self.parse_error is None

    def require_soap_envelope(self) -> Envelope:
        if self.soap_envelope is None:
            raise ValueError("Message carries no SOAP envelope")
        return self.soap_envelope

    @property
    def soap_envelope_xml(self) -> bytes:
        soap_envelope = self.require_soap_envelope()
        if soap_envelope.etree_element is not None:
            return etree.tostring(soap_envelope.etree_element, pretty_print=True)
        return etree.tostring(
            soap_envelope.dump_to_xml("{http://www.w3.org/2003/05/soap-envelope}Envelope"), pretty_print=True
        )

    def get_request_data(self) -> tuple[bytes, str]:
        envelope_element = self.require_soap_envelope().dump_to_xml(
            "{http://www.w3.org/2003/05/soap-envelope}Envelope"
        )
        soap_xml = etree.tostring(envelope_element)
        return MIMEHandler.build_request_data(
            soap_xml,
            attachments=list(self.mime_attachments.items()),
        )

    def get_http_headers(self, boundary: str, user_agent: str | None = None) -> dict[str, str]:
        return MIMEHandler.build_request_headers(boundary=boundary, user_agent=user_agent)

    @classmethod
    def pre_validate(
        cls,
        soap_envelope_element: etree._Element,
    ) -> tuple[str, str]:
        """These IDs are required when sending an error or non-repudiation receipt"""
        message_id = soap_envelope_element.findtext(
            "S12:Header/eb3:Messaging/eb3:UserMessage/eb3:MessageInfo/eb3:MessageId",
            namespaces=NAMESPACES,
        )
        messaging = soap_envelope_element.find(
            "S12:Header/eb3:Messaging",
            namespaces=NAMESPACES,
        )
        if messaging is None:
            raise MessagingNotFoundException(detail="Missing ebMS Messaging header in SOAP envelope")
        messaging_id = messaging.get(
            "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id"
        )
        if not message_id or not messaging_id:
            raise MessageIdNotFoundException(detail="Missing MessageId or Messaging wsu:Id in SOAP envelope")
        return message_id, messaging_id

    @classmethod
    def get_addressed_to(cls, party_to_element: etree._Element | None) -> AS4PartyIdentity:
        if party_to_element is None:
            raise PartyToNotFoundException(detail="Missing PartyInfo/To element in UserMessage")
        return AS4PartyIdentity.from_party(PartyTo.model_validate_etree(party_to_element))

    @classmethod
    def parse(
        cls,
        parse_context: AS4ParseContext,
        soap_bytes: bytes,
        mime_attachments: dict[str, bytes],
    ) -> Self:
        fields: dict[str, Any] = {}
        error: BaseAS4ReceiptableError | None = None
        try:
            soap_envelope_element = parse_xml(soap_bytes)
            party_to_element = soap_envelope_element.find(PARTY_TO_PATH, namespaces=NAMESPACES)
            message_id, messaging_id = cls.pre_validate(soap_envelope_element)
            fields["message_id"], fields["messaging_id"] = message_id, messaging_id
            fields["addressed_to"] = cls.get_addressed_to(party_to_element)
            fields = cls.process(fields, parse_context, soap_envelope_element, mime_attachments)
        except etree.XMLSyntaxError:
            error = MalformedSoapEnvelopeException()
        except pydantic_core.ValidationError as validation_exception:
            error = BaseAS4ReceiptableError.from_validation_error(validation_exception)
        except BaseAS4ReceiptableError as exception:
            error = exception
        return cls(parse_error=error, **fields)

    @classmethod
    def signature_coverage(
        cls,
        signature: Signature,
        elements_by_id: dict[str, etree._Element],
        payload_hrefs: set[str],
    ) -> set[str]:
        covered = set()
        signed_payloads = set()
        for reference in signature.signed_info.references:
            uri = reference.uri or ""
            if uri.startswith("cid:"):
                signed_payloads.add(uri)
                continue
            target = elements_by_id.get(uri.removeprefix("#"))
            if target is not None and (kind := COVERAGE_BY_TAG.get(target.tag)):
                covered.add(kind)
        if payload_hrefs <= signed_payloads:
            covered.add("payloads")
        return covered

    @classmethod
    def verify_signature_coverage(
        cls,
        signature: Signature,
        elements_by_id: dict[str, etree._Element],
        payload_hrefs: set[str],
        required_coverage: frozenset[str],
    ) -> None:
        missing = required_coverage - cls.signature_coverage(signature, elements_by_id, payload_hrefs)
        if missing:
            raise SignatureCoverageException(sorted(missing))

    def get_remote_party(self) -> AS4ExternalParty:
        if self.signer_certificate is None:
            raise RemotePartyNotVerifiedError(
                "Message signature has not been verified, so the access point that sent it is not established"
            )
        if self.soap_envelope is None:
            raise RemotePartyNotVerifiedError("Message carries no SOAP envelope to read eb:From from")
        user_message = self.soap_envelope.header.messaging.user_message
        if user_message is None:
            raise UserMessageNotFoundException()
        return AS4ExternalParty(
            identity=AS4PartyIdentity.from_party(user_message.party_info.party_from),
            credentials=AS4BaseCredentials(certificate=self.signer_certificate),
        )

    @property
    def conversation_id(self) -> str | None:
        if self.soap_envelope is None:
            return None
        user_message = self.soap_envelope.header.messaging.user_message
        if user_message is None:
            return None
        return user_message.collaboration_info.conversation_id.value

    @property
    def signature_references(self) -> list[DsigReference]:
        if self.soap_envelope is None or self.soap_envelope.header.security.signature is None:
            return []
        return self.soap_envelope.header.security.signature.signed_info.references

    @property
    def signed_references(self) -> list[ComparableReferenceFields]:
        return [ComparableReferenceFields.from_reference(reference) for reference in self.signature_references]

    @classmethod
    def verify_reference_digests(
        cls,
        signature: Signature,
        elements_by_id: dict[str, etree._Element],
    ) -> None:
        for reference in signature.signed_info.references:
            uri = reference.uri or ""
            if uri.startswith("cid:"):
                continue
            target = elements_by_id.get(uri.removeprefix("#"))
            if target is None:
                raise ReferenceTargetNotFoundException(uri)
            try:
                matches = reference.digest_matches(target)
            except UnsupportedDigestAlgorithm as exception:
                raise UnsupportedDigestAlgorithmException(str(exception)) from exception
            except UnsupportedTransform as exception:
                raise UnsupportedTransformException(str(exception)) from exception
            if not matches:
                raise DigestMismatchException(uri)

    @classmethod
    def verify_attachment_digests(
        cls,
        signature: Signature,
        signed_attachments: dict[str, bytes],
    ) -> None:
        """AS4 3.1 compresses before signing, so these run on decrypted but still compressed bytes."""
        for reference in signature.signed_info.references:
            uri = reference.uri or ""
            if not uri.startswith("cid:"):
                continue
            content = signed_attachments.get(uri.removeprefix("cid:"))
            if content is None:
                raise ReferenceTargetNotFoundException(uri)
            try:
                matches = reference.digest_matches_bytes(content)
            except UnsupportedDigestAlgorithm as exception:
                raise UnsupportedDigestAlgorithmException(str(exception)) from exception
            except UnsupportedTransform as exception:
                raise UnsupportedTransformException(str(exception)) from exception
            if not matches:
                raise DigestMismatchException(uri)

    @classmethod
    def resolve_signer(
        cls,
        security_policy: SecurityPolicy,
        party_from: PartyFrom,
        embedded_certificate: x509.Certificate | None,
    ) -> x509.Certificate:
        try:
            return security_policy.signer_resolver(party_from, embedded_certificate)
        except UntrustedSignerError as exception:
            raise UntrustedSignerException() from exception

    @classmethod
    def get_verified_signature(
        cls,
        parse_context: AS4ParseContext,
        security: Security,
        soap_envelope: Envelope,
        elements_by_id: dict[str, etree._Element],
    ) -> tuple[Signature | None, x509.Certificate | None]:
        if security.signature is None:
            if parse_context.security_policy.sign_required:
                raise SignatureRequiredException()
            return None, None
        signature = security.signature
        security_token_references = signature.key_info.security_token_reference
        signature_bst_uri = security_token_references[0].reference.uri if security_token_references else None
        if not signature_bst_uri:
            raise SignatureSecurityTokenReferenceNotFoundException()
        signature_bst = next(
            (bst for bst in security.binary_security_tokens if signature_bst_uri == f"#{bst.bst_id}"),
            None,
        )
        if signature_bst is None:
            raise SignatureSecurityTokenReferenceNotFoundException()

        user_message = soap_envelope.header.messaging.user_message
        if user_message is None:
            raise UserMessageNotFoundException()
        try:
            embedded_certificate = signature_bst.x509_certificate
        except UnsupportedSecurityTokenType as exception:
            raise UnsupportedSecurityTokenTypeException(str(exception)) from exception
        signer_certificate = cls.resolve_signer(
            parse_context.security_policy, user_message.party_info.party_from, embedded_certificate
        )
        try:
            signature.verify(signer_certificate)
        except UnsupportedSignatureAlgorithm as exception:
            raise UnsupportedSignatureAlgorithmException(str(exception)) from exception
        except UnsupportedTransform as exception:
            raise UnsupportedTransformException(str(exception)) from exception
        except InvalidSignature as exception:
            raise SignatureVerificationFailedException() from exception
        declared_payloads = user_message.payload_info
        cls.verify_signature_coverage(
            signature,
            elements_by_id,
            {part.href for part in declared_payloads.part_info if part.href} if declared_payloads else set(),
            parse_context.security_policy.required_coverage,
        )

        if parse_context.security_policy.verify_digests:
            cls.verify_reference_digests(signature, elements_by_id)

        return signature, signer_certificate

    @classmethod
    def get_decrypted_data(
        cls,
        parse_context: AS4ParseContext,
        security: Security,
        mime_attachments: dict[str, bytes],
    ) -> dict[str, bytes]:
        if security.encrypted_key is None:
            if parse_context.security_policy.encrypt_required:
                raise EncryptionRequiredException()
            return {}
        cipher_data = security.encrypted_key.cipher_data
        cipher_value = cipher_data.cipher_value

        if not cipher_value or not cipher_value.value:
            raise CipherValueNotFoundException()

        key_transport_algorithm = security.encrypted_key.encryption_method.algorithm
        if key_transport_algorithm != EncryptionAlgorithm.RSA_OAEP:
            raise UnsupportedEncryptionAlgorithmException(key_transport_algorithm)

        try:
            encrypted_session_key = base64.b64decode(cipher_value.value, validate=True)
            session_key = parse_context.local_party.credentials.private_key.decrypt(
                encrypted_session_key,
                # TODO honour the declared ds:DigestMethod and xenc11:MGF instead of assuming SHA-256
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=b"",
                ),
            )
        except ValueError as exception:
            raise DecryptionFailedException() from exception
        decrypted_data: dict[str, bytes] = {}
        for encrypted_data_reference in security.encrypted_key.reference_list.data_reference:
            encrypted_data_uri = encrypted_data_reference.uri
            if not encrypted_data_uri:
                raise EncryptedDataReferenceNotFoundException()
            encrypted_data = security.get_encrypted_data(encrypted_data_uri[1:])
            if not encrypted_data:
                raise EncryptedDataNotFoundException(encrypted_data_uri=encrypted_data_uri)
            encryption_method = encrypted_data.encryption_method
            if not (cipher_reference := encrypted_data.cipher_data.cipher_reference) or not (
                uri := cipher_reference.uri
            ):
                raise CipherReferenceNotFoundException()
            if not uri.startswith("cid:"):
                raise CipherReferenceNotFoundException()
            encrypted_attachment_id = uri.removeprefix("cid:")
            if encrypted_attachment_id not in mime_attachments:
                raise EncryptedAttachmentNotFoundException(encrypted_attachment_id)
            encrypted_attachment_bytes = mime_attachments[encrypted_attachment_id]
            match encryption_method.algorithm:
                case EncryptionAlgorithm.AES128_GCM:
                    nonce, data = encrypted_attachment_bytes[:12], encrypted_attachment_bytes[12:]
                    try:
                        decrypted_attachment_bytes = AESGCM(session_key).decrypt(nonce, data, None)
                    except (ValueError, InvalidTag) as exception:
                        raise DecryptionFailedException() from exception
                    decrypted_data[encrypted_attachment_id] = decrypted_attachment_bytes
                case _:
                    raise UnsupportedEncryptionAlgorithmException(encryption_method.algorithm)
        return decrypted_data

    @classmethod
    def process(
        cls,
        fields: dict[str, Any],
        parse_context: AS4ParseContext,
        soap_envelope_element: etree._Element,
        mime_attachments: dict[str, bytes],
    ) -> dict[str, Any]:
        fields["mime_attachments"] = mime_attachments

        soap_envelope = Envelope.model_validate_etree(soap_envelope_element)
        fields["soap_envelope"] = soap_envelope
        elements_by_id = index_elements_by_id(soap_envelope_element)

        security = soap_envelope.header.security
        signature, signer_certificate = cls.get_verified_signature(
            parse_context, security, soap_envelope, elements_by_id
        )
        fields["signer_certificate"] = signer_certificate
        decrypted_data = cls.get_decrypted_data(parse_context, security, mime_attachments)
        fields["decrypted_data"] = decrypted_data

        if signature is not None and parse_context.security_policy.verify_digests:
            cls.verify_attachment_digests(signature, dict(decrypted_data))

        if soap_envelope.header.messaging.user_message is None:
            raise UserMessageNotFoundException()
        payload_info = soap_envelope.header.messaging.user_message.payload_info
        if payload_info is None:
            raise PayloadInfoNotFoundException()
        for part_info in payload_info.part_info:
            if not part_info.href:
                continue
            identifier = part_info.href.removeprefix("cid:")
            if identifier not in mime_attachments:
                raise PartInfoWithoutMimePartException(part_info.href)
            decrypted_part_content = decrypted_data.get(identifier)
            if decrypted_part_content is None:
                continue
            decrypted_part_content = part_info.part_properties.decompress(
                decrypted_part_content=decrypted_part_content,
                maximum_size=parse_context.security_policy.maximum_decompressed_size,
            )
            decrypted_data[identifier] = decrypted_part_content

        return fields
