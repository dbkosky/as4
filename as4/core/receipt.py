import base64
from datetime import UTC, datetime
from typing import Self

import pydantic_core
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree
from as4 import const
from as4.core.common import AS4InternalParty, index_elements_by_id
from as4.errors import BaseAS4ReceiptableError, ReceiptVerificationError
from as4.core.message import AS4Message
from as4.core.references import AS4References
from as4.models.common import NAMESPACES
from as4.models.dsig.reference import ComparableReferenceFields
from as4.models.dsig.key_info import KeyInfo
from as4.models.dsig.reference import DigestAlgorithm, UnsupportedDigestAlgorithm, UnsupportedTransform
from as4.models.dsig.reference import Reference as DsigReference
from as4.models.dsig.signature import (
    CanonicalizationMethod,
    Signature,
    SignatureMethod,
    SignatureValue,
    SignedInfo,
    UnsupportedSignatureAlgorithm,
)
from as4.models.ebbp.non_repudiation_information import MessagePartNRInformation, NonRepudiationInformation
from as4.models.ebms.description import Description
from as4.models.ebms.message_info import MessageId, MessageInfo, RefToMessageId, Timestamp
from as4.models.ebms.messaging import Messaging
from as4.models.ebms.signal_message import Error, ErrorDetail, Receipt, SignalMessage
from as4.models.soap.envelope import Body, Envelope
from as4.models.soap.header import Header
from as4.models.wsse.binary_security_token import BinarySecurityToken
from as4.models.wsse.security import Security
from as4.models.wsse.security_token_reference import Reference as WsseReference
from as4.models.wsse.security_token_reference import SecurityTokenReference
from as4.utils.xml_parser import parse_xml
from pydantic import BaseModel, ConfigDict


class AS4ReceiptBuilderArgs(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    namespace_map: dict[str, str] = NAMESPACES

    referenced_message_id: str
    referenced_messaging_id: str

    # Only the credentials are used. A SignalMessage has no eb3:PartyInfo, so the identity has
    # nowhere to go, but the whole party is carried for symmetry with the build side.
    local_party: AS4InternalParty


class AS4SuccessReceiptBuilderArgs(AS4ReceiptBuilderArgs):
    non_repudiated_references: list[DsigReference]
    # original_timestamp: str


class AS4ErrorReceiptBuilderArgs(AS4ReceiptBuilderArgs):
    error_code: str
    error_short_description: str
    error_severity: str
    error_detail: str
    error_description: str
    error_category: str


class AS4Receipt(BaseModel):
    soap_envelope: Envelope | None = None
    original_message_id: str | None = None
    references: AS4References | None = None

    profile_name: str | None = None

    @classmethod
    def parse(
        cls,
        receipt_data: bytes,
        expected_signer: x509.Certificate,
    ) -> Self:
        try:
            soap_envelope_element = parse_xml(receipt_data)
            soap_envelope = Envelope.model_validate_etree(soap_envelope_element)
            signal_message = soap_envelope.header.messaging.signal_message
        except (etree.XMLSyntaxError, pydantic_core.ValidationError, BaseAS4ReceiptableError) as exception:
            raise ReceiptVerificationError(f"Signal is not a readable ebMS signal message: {exception}") from exception
        original_message_id = None
        if signal_message and signal_message.message_info.ref_to_message_id:
            original_message_id = signal_message.message_info.ref_to_message_id.value
        receipt = cls(
            soap_envelope=soap_envelope,
            original_message_id=original_message_id,
        )
        if receipt.error is None and not original_message_id:
            raise ReceiptVerificationError("Receipt names no eb:RefToMessageId, so it proves delivery of nothing")
        receipt.verify_signature(soap_envelope_element, expected_signer)
        return receipt

    @classmethod
    def peek_original_message_id(cls, signal_data: bytes) -> str | None:
        try:
            soap_envelope_element = parse_xml(signal_data)
        except etree.XMLSyntaxError:
            return None
        return soap_envelope_element.findtext(
            "S12:Header/eb3:Messaging/eb3:SignalMessage/eb3:MessageInfo/eb3:RefToMessageId",
            namespaces=NAMESPACES,
        )

    def verify_signature(self, soap_envelope_element: etree._Element, expected_signer: x509.Certificate) -> None:
        if self.soap_envelope is None:
            raise ReceiptVerificationError("Receipt carries no SOAP envelope")
        security = self.soap_envelope.header.security
        signature = security.signature
        if signature is None:
            raise ReceiptVerificationError("Receipt carries no ds:Signature")
        security_token_references = signature.key_info.security_token_reference
        signature_bst_uri = security_token_references[0].reference.uri if security_token_references else None
        embedded_certificate = next(
            (bst.x509_certificate for bst in security.binary_security_tokens if signature_bst_uri == f"#{bst.bst_id}"),
            None,
        )
        if embedded_certificate is None:
            raise ReceiptVerificationError("Receipt signature references no security token")
        if embedded_certificate != expected_signer:
            raise ReceiptVerificationError(
                f"Receipt is signed by {embedded_certificate.subject.rfc4514_string()}, "
                f"not {expected_signer.subject.rfc4514_string()}"
            )
        try:
            signature.verify(expected_signer)
        except InvalidSignature as exception:
            raise ReceiptVerificationError("Receipt signature does not verify") from exception
        except (UnsupportedSignatureAlgorithm, UnsupportedTransform) as exception:
            raise ReceiptVerificationError(f"Receipt signature is not verifiable: {exception}") from exception

        elements_by_id = index_elements_by_id(soap_envelope_element)
        if "messaging" not in AS4Message.signature_coverage(signature, elements_by_id, set()):
            raise ReceiptVerificationError("Receipt signature does not cover eb:Messaging")
        for reference in signature.signed_info.references:
            uri = reference.uri or ""
            target = elements_by_id.get(uri.removeprefix("#"))
            if target is None:
                raise ReceiptVerificationError(f"Receipt signature references {uri}, which is not in the document")
            try:
                matches = reference.digest_matches(target)
            except (UnsupportedDigestAlgorithm, UnsupportedTransform) as exception:
                raise ReceiptVerificationError(
                    f"Receipt reference {uri} is not verifiable: {exception}"
                ) from exception
            if not matches:
                raise ReceiptVerificationError(f"Receipt digest for {uri} does not match the signed element")

    @property
    def non_repudiated_references(self) -> list[ComparableReferenceFields]:
        receipt = self.receipt
        if receipt is None or receipt.non_repudiation_information is None:
            return []
        return [
            ComparableReferenceFields.from_reference(reference)
            for part in receipt.non_repudiation_information.message_part_nr_information
            for reference in part.references
        ]

    def verify_non_repudiation(
        self,
        sent_references: list[ComparableReferenceFields],
        required_references: list[ComparableReferenceFields] | None = None,
    ) -> None:
        if self.receipt is None:
            raise ReceiptVerificationError("Receipt carries no eb:Receipt to compare against")
        if required_references is not None and not required_references:
            raise ReceiptVerificationError("No references were required, so this receipt would prove nothing")
        acknowledged = self.non_repudiated_references
        for reference in acknowledged:
            if reference not in sent_references:
                raise ReceiptVerificationError(f"Receipt acknowledges {reference.uri!r}, which was not sent")
        for reference in required_references if required_references is not None else sent_references:
            if reference not in acknowledged:
                raise ReceiptVerificationError(f"Receipt does not acknowledge {reference.uri!r}")

    @property
    def errors(self) -> list[Error]:
        if not self.soap_envelope:
            return []
        signal_message = self.soap_envelope.header.messaging.signal_message
        if not signal_message:
            return []
        return signal_message.errors

    @property
    def error(self) -> Error | None:
        return self.errors[0] if self.errors else None

    @property
    def receipt(self) -> Receipt | None:
        if not self.soap_envelope:
            return None
        if not self.soap_envelope.header.messaging.signal_message:
            return None
        return self.soap_envelope.header.messaging.signal_message.receipt

    @property
    def success(self) -> bool:
        return bool(self.receipt)

    @classmethod
    def for_message(
        cls,
        message: AS4Message,
        local_party: AS4InternalParty,
        references: AS4References | None = None,
    ) -> Self:
        if message.parse_error is not None:
            return cls.create_error_signal_from_exception(
                exception=message.parse_error,
                local_party=local_party,
                references=references,
                referenced_message_id=message.message_id,
                referenced_messaging_id=message.messaging_id,
            )
        return cls.create_non_repudiation_receipt(
            referenced_message_id=message.message_id,
            referenced_messaging_id=message.messaging_id,
            non_repudiated_references=message.signature_references,
            local_party=local_party,
            references=references,
        )

    @classmethod
    def create_non_repudiation_receipt(
        cls,
        referenced_message_id: str,
        referenced_messaging_id: str,
        non_repudiated_references: list[DsigReference],
        local_party: AS4InternalParty,
        references: AS4References | None = None,
    ) -> Self:
        builder_args = AS4SuccessReceiptBuilderArgs(
            referenced_message_id=referenced_message_id,
            referenced_messaging_id=referenced_messaging_id,
            non_repudiated_references=non_repudiated_references,
            local_party=local_party,
        )
        if not references:
            references = AS4References()
        return cls(
            soap_envelope=cls.get_success_soap_envelope(builder_args, references),
            references=references,
        )

    @classmethod
    def create_error_signal(
        cls,
        error_code: str,
        short_description: str,
        description: str,
        severity: str,
        detail: str,
        category: str,
        referenced_message_id: str,
        referenced_messaging_id: str,
        local_party: AS4InternalParty,
        references: AS4References | None = None,
    ) -> Self:
        builder_args = AS4ErrorReceiptBuilderArgs(
            local_party=local_party,
            error_code=error_code,
            error_short_description=short_description,
            error_description=description,
            error_severity=severity,
            error_detail=detail,
            error_category=category,
            referenced_message_id=referenced_message_id,
            referenced_messaging_id=referenced_messaging_id,
        )
        if not references:
            references = AS4References()
        return cls(soap_envelope=cls.get_error_soap_envelope(builder_args, references), references=references)

    @classmethod
    def create_error_signal_from_exception(
        cls,
        exception: BaseAS4ReceiptableError,
        local_party: AS4InternalParty,
        references: AS4References | None = None,
        referenced_message_id: str = "",
        referenced_messaging_id: str = "",
    ) -> Self:
        return cls.create_error_signal(
            error_code=exception.error_code,
            short_description=exception.short_description,
            description=exception.description,
            severity=exception.severity,
            detail=exception.detail,
            category=exception.category,
            referenced_message_id=referenced_message_id,
            referenced_messaging_id=referenced_messaging_id,
            local_party=local_party,
            references=references,
        )

    def require_soap_envelope(self) -> Envelope:
        if self.soap_envelope is None:
            raise ValueError("Receipt carries no SOAP envelope")
        return self.soap_envelope

    def get_request_data(self) -> tuple[dict[str, str], bytes]:
        envelope_element = self.require_soap_envelope().dump_to_xml(
            "{http://www.w3.org/2003/05/soap-envelope}Envelope",
            namespaces=NAMESPACES,
        )
        soap_xml = etree.tostring(envelope_element)
        return {"Content-Type": "application/soap+xml;charset=utf-8"}, soap_xml

    @classmethod
    def get_error_ref_to_message_id(cls, builder_args: AS4ErrorReceiptBuilderArgs) -> RefToMessageId | None:
        if not builder_args.referenced_message_id:
            return None
        return RefToMessageId(value=builder_args.referenced_message_id)

    @classmethod
    def get_success_signal_message(
        cls,
        builder_args: AS4SuccessReceiptBuilderArgs,
        references: AS4References,
    ) -> SignalMessage:
        message_info = MessageInfo(
            timestamp=Timestamp(value=datetime.now(UTC)),
            message_id=MessageId(value=references.message_id),
            ref_to_message_id=RefToMessageId(value=builder_args.referenced_message_id),
        )
        message_part_non_repudiation_information = [
            MessagePartNRInformation(
                references=[ref],
            )
            for ref in builder_args.non_repudiated_references
        ]
        non_repudiation_information = NonRepudiationInformation(
            message_part_nr_information=message_part_non_repudiation_information,
        )
        receipt = Receipt(non_repudiation_information=non_repudiation_information)
        return SignalMessage(
            message_info=message_info,
            receipt=receipt,
        )

    @classmethod
    def get_error_signal_message(
        cls,
        builder_args: AS4ErrorReceiptBuilderArgs,
        references: AS4References,
    ) -> SignalMessage:
        message_info = MessageInfo(
            timestamp=Timestamp(value=datetime.now(UTC)),
            message_id=MessageId(value=references.message_id),
            ref_to_message_id=cls.get_error_ref_to_message_id(builder_args),
        )
        error = Error(
            category=builder_args.error_category,
            error_code=builder_args.error_code,
            ref_to_message_in_error=builder_args.referenced_message_id or None,
            severity=builder_args.error_severity,
            short_description=builder_args.error_short_description,
            description=Description(value=builder_args.error_description),
            error_detail=ErrorDetail(value=builder_args.error_detail),
        )
        return SignalMessage(message_info=message_info, errors=[error])

    @classmethod
    def get_messaging(
        cls,
        builder_args: AS4ReceiptBuilderArgs,
        references: AS4References,
        signal_message: SignalMessage,
    ) -> Messaging:
        return Messaging(
            signal_messages=[signal_message],
            messaging_id=references.messaging_id,
            w3_org_2003_05_soap_envelope_must_understand=True,
        )

    @classmethod
    def get_signed_info(
        cls,
        builder_args: AS4ReceiptBuilderArgs,
        references: AS4References,
        messaging: Messaging,
        body: Body,
    ) -> SignedInfo:
        return SignedInfo(
            references=[
                cls.get_messaging_digest_reference(builder_args, references, messaging),
                cls.get_body_digest_reference(references, body),
            ],
            canonicalization_method=CanonicalizationMethod(algorithm=const.XML_EXC_C14N),
            signature_method=SignatureMethod(algorithm=const.DSIG_RSA_SHA256),
        )

    @classmethod
    def get_body_digest_reference(cls, references: AS4References, body: Body) -> DsigReference:
        return DsigReference.for_element(
            uri=f"#{references.body_id}",
            element=body.dump_to_xml("{http://www.w3.org/2003/05/soap-envelope}Body"),
            digest_algorithm=DigestAlgorithm.SHA256,
        )

    @classmethod
    def get_messaging_digest_reference(
        cls,
        builder_args: AS4ReceiptBuilderArgs,
        references: AS4References,
        messaging: Messaging,
    ) -> DsigReference:
        messaging_clark_name = "{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Messaging"
        return DsigReference.for_element(
            uri=f"#{references.messaging_id}",
            element=messaging.dump_to_xml(messaging_clark_name),
            digest_algorithm=DigestAlgorithm.SHA256,
        )

    @classmethod
    def get_local_binary_security_token(
        cls,
        builder_args: AS4ReceiptBuilderArgs,
        references: AS4References,
    ) -> BinarySecurityToken:
        return BinarySecurityToken(
            encoding_type=const.BASE_64_BINARY,
            value_type=const.X509_V3,
            bst_id=references.signature_bst_id,
            value=base64.b64encode(
                builder_args.local_party.credentials.certificate.public_bytes(serialization.Encoding.DER)
            ),
        )

    @classmethod
    def get_signature(
        cls,
        builder_args: AS4ReceiptBuilderArgs,
        references: AS4References,
        signed_info: SignedInfo,
    ) -> Signature:
        signed_info.etree_element = signed_info.dump_to_xml(
            "{http://www.w3.org/2000/09/xmldsig#}SignedInfo",
            namespaces=builder_args.namespace_map,
        )
        signed_info_canonicalised = signed_info.signed_info_canonicalized
        signature_bytes = builder_args.local_party.credentials.private_key.sign(
            signed_info_canonicalised, padding.PKCS1v15(), hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")
        wsse_reference = WsseReference(
            uri=f"#{references.signature_bst_id}",
            value_type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
        )
        return Signature(
            signature_id=references.signature_id,
            key_info=KeyInfo(
                key_info_id=references.key_info_id,
                security_token_reference=[
                    SecurityTokenReference(
                        security_token_reference_id=references.signature_security_token_reference_id,
                        reference=wsse_reference,
                    ),
                ],
            ),
            signature_value=SignatureValue(value=signature_b64),
            signed_info=signed_info,
        )

    @classmethod
    def get_success_soap_envelope(
        cls,
        builder_args: AS4SuccessReceiptBuilderArgs,
        references: AS4References,
    ) -> Envelope:
        signal_message = cls.get_success_signal_message(
            builder_args=builder_args,
            references=references,
        )
        messaging = cls.get_messaging(
            builder_args=builder_args,
            references=references,
            signal_message=signal_message,
        )
        body = Body(body_id=references.body_id)
        signed_info = cls.get_signed_info(
            builder_args=builder_args,
            references=references,
            messaging=messaging,
            body=body,
        )
        signature = cls.get_signature(
            builder_args=builder_args,
            references=references,
            signed_info=signed_info,
        )
        return Envelope(
            header=Header(
                security=Security(
                    binary_security_tokens=[
                        cls.get_local_binary_security_token(builder_args, references),
                    ],
                    signature=signature,
                ),
                messaging=messaging,
            ),
            body=body,
        )

    @classmethod
    def get_error_soap_envelope(
        cls,
        builder_args: AS4ErrorReceiptBuilderArgs,
        references: AS4References,
    ) -> Envelope:
        signal_message = cls.get_error_signal_message(
            builder_args=builder_args,
            references=references,
        )
        messaging = cls.get_messaging(
            builder_args=builder_args,
            references=references,
            signal_message=signal_message,
        )
        body = Body(body_id=references.body_id)
        signed_info = cls.get_signed_info(
            builder_args=builder_args,
            references=references,
            messaging=messaging,
            body=body,
        )
        signature = cls.get_signature(
            builder_args=builder_args,
            references=references,
            signed_info=signed_info,
        )
        return Envelope(
            header=Header(
                security=Security(
                    binary_security_tokens=[
                        cls.get_local_binary_security_token(builder_args, references),
                    ],
                    signature=signature,
                ),
                messaging=messaging,
            ),
            body=body,
        )
