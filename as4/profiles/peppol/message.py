import base64
import gzip
from datetime import UTC, datetime
from typing import Any, ClassVar, Self

import pydantic_core
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree
from as4 import const
from as4.core.common import AS4ExternalParty, AS4InternalParty
from as4.core.context import AS4ParseContext
from as4.core.message import AS4Message
from as4.core.references import AS4References
from as4.models.common import NAMESPACES
from as4.models.dsig.key_info import KeyInfo
from as4.models.dsig.reference import DigestAlgorithm, DigestMethod
from as4.models.dsig.reference import Reference as DsigReference
from as4.models.dsig.signature import CanonicalizationMethod, Signature, SignatureMethod, SignatureValue, SignedInfo
from as4.models.dsig.transforms import Transform as DsigTransform
from as4.models.dsig.transforms import TransformAlgorithm
from as4.models.ebms.message_info import MessageId, MessageInfo, Timestamp
from as4.models.ebms.messaging import Messaging
from as4.models.ebms.user_message import (
    Action,
    AgreementRef,
    CollaborationInfo,
    ConversationId,
    MessageProperties,
    PartInfo,
    PartProperties,
    PartyInfo,
    PayloadInfo,
    Property,
    Service,
    UserMessage,
)
from as4.models.soap.envelope import Body, Envelope
from as4.models.soap.header import Header
from as4.models.unece import sbdh
from as4.models.wsse.binary_security_token import BinarySecurityToken
from as4.models.wsse.security import Security
from as4.models.wsse.security_token_reference import Reference as WsseReference
from as4.models.wsse.security_token_reference import SecurityTokenReference
from as4.models.xenc.encrypted_type import (
    MGF,
    CipherData,
    CipherReference,
    CipherValue,
    EncryptedKey,
    EncryptedType,
    EncryptionAlgorithm,
    EncryptionMethod,
)
from as4.models.xenc.encrypted_type import Transforms as XencTransforms
from as4.models.xenc.reference import Reference as XencReference
from as4.models.xenc.reference import ReferenceList
from as4.profiles.peppol.document_identifier import BusdoxDocidQnsDocumentIdentifier
from as4.errors import ParticipantNotServicedError, UserMessageNotFoundException
from as4.profiles.peppol.exceptions import (
    PeppolNotServicedException,
    PeppolPartyIdentifierException,
    PeppolSBDHException,
)
from as4.resources.schemas.vendor.sbdh import SBDHSchema
from as4.utils.cipher_handler import CipherHandler
from as4.utils.xml_parser import parse_xml
from pydantic import BaseModel, ConfigDict, Field


class PeppolAS4MessageBuilderArgs(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    namespace_map: dict[str, str] = NAMESPACES
    sender: str
    recipient: str
    document_type_identifier: BusdoxDocidQnsDocumentIdentifier = Field(description="Peppol document type identifier")
    document_identification_instance_identifier: str
    process_identifier: str
    c1_country_id: str


class PeppolAS4Message(AS4Message):

    # Peppol-specific fields
    sender: str | None = None
    recipient: str | None = None
    document_type_identifier_value: str | None = None
    document_type_identifier_scheme: str | None = None
    process_identifier: str | None = None

    MANDATORY_SBDH_SCOPE_TYPE_VALUES: ClassVar[set[str]] = {"PROCESSID", "DOCUMENTID", "COUNTRY_C1"}

    @classmethod
    def verify_party_identifiers(cls, envelope: Envelope | None) -> None:
        user_message = envelope.header.messaging.user_message if envelope is not None else None
        if user_message is None:
            raise UserMessageNotFoundException()
        party_info = user_message.party_info
        for element, party in (("From", party_info.party_from), ("To", party_info.party_to)):
            if party.party_id.type_value != const.PEPPOL_PARTY_IDENTIFIER_TYPE:
                raise PeppolPartyIdentifierException(element, party.party_id.type_value)

    @property
    def message_properties(self) -> MessageProperties | None:
        if self.soap_envelope is None:
            return None
        user_message = self.soap_envelope.header.messaging.user_message
        return None if user_message is None else user_message.message_properties

    @classmethod
    def verify_participants_agree(
        cls,
        properties: MessageProperties | None,
        sender: sbdh.Identifier,
        recipient: sbdh.Identifier,
    ) -> None:
        for name, declared, identifier in (
            (const.ORIGINAL_SENDER, properties.original_sender if properties else None, sender),
            (const.FINAL_RECIPIENT, properties.final_recipient if properties else None, recipient),
        ):
            if declared is None:
                detail = f"SBDH names {identifier.value!r} where the {name} property is absent"
            elif (declared.value, declared.property_type) != (identifier.value, identifier.authority):
                detail = (
                    f"SBDH names {identifier.value!r} under {identifier.authority!r} where the {name} "
                    f"property names {declared.value!r} under {declared.property_type!r}"
                )
            else:
                continue
            raise PeppolSBDHException(detail=detail)

    @classmethod
    def process(
        cls,
        fields: dict[str, Any],
        parse_context: AS4ParseContext,
        soap_envelope_element: etree._Element,
        mime_attachments: dict[str, bytes],
    ) -> dict[str, Any]:
        fields = super().process(fields, parse_context, soap_envelope_element, mime_attachments)
        try:
            return cls.process_sbdh(fields, parse_context)
        except pydantic_core.ValidationError as validation_exception:
            validation_error, *_ = validation_exception.errors()
            raise PeppolSBDHException.from_pydantic_error(validation_error) from validation_exception

    @classmethod
    def process_sbdh(cls, fields: dict[str, Any], parse_context: AS4ParseContext) -> dict[str, Any]:
        cls.verify_party_identifiers(fields["soap_envelope"])

        first_attachment_id = next(iter(fields["mime_attachments"]), None)
        payload = fields["decrypted_data"].get(first_attachment_id)
        if payload is None:
            raise PeppolSBDHException(detail="The first MIME attachment carries no decrypted payload")
        try:
            sbd_element = parse_xml(payload)
        except etree.XMLSyntaxError as exception:
            raise PeppolSBDHException(detail="The first MIME attachment is not well-formed XML") from exception

        sbdh_element = sbd_element.find(
            "{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}StandardBusinessDocumentHeader"
        )
        if sbdh_element is None:
            raise PeppolSBDHException(detail="Decrypted payload carries no StandardBusinessDocumentHeader")
        validation_error = SBDHSchema.validation_error(sbdh_element)
        if validation_error is not None:
            reported = f": {validation_error}" if validation_error else ""
            raise PeppolSBDHException(detail=f"The SBDH is not schema valid{reported}")

        sbd_object = sbdh.StandardBusinessDocument.model_validate_etree(sbd_element)
        sbdh_header = sbd_object.standard_business_document_header
        fields["sender"] = sbdh_header.sender.identifier.value
        fields["recipient"] = sbdh_header.receiver.identifier.value
        if parse_context.security_policy.verify_participants:
            user_message = fields["soap_envelope"].header.messaging.user_message
            cls.verify_participants_agree(
                None if user_message is None else user_message.message_properties,
                sbdh_header.sender.identifier,
                sbdh_header.receiver.identifier,
            )
        if parse_context.accept_participant is not None:
            try:
                parse_context.accept_participant(fields["recipient"])
            except ParticipantNotServicedError as exception:
                raise PeppolNotServicedException() from exception

        scopes = {scope.scope_type.value: scope for scope in sbdh_header.business_scope.scopes}
        if missing_scopes := (cls.MANDATORY_SBDH_SCOPE_TYPE_VALUES.difference(scopes)):
            raise PeppolSBDHException(detail=f"Missing expected scopes with scope types: {missing_scopes}")
        document_scope, process_scope = scopes["DOCUMENTID"], scopes["PROCESSID"]
        fields["document_type_identifier_value"] = document_scope.instance_identifier.value
        fields["document_type_identifier_scheme"] = (
            document_scope.identifier.value if document_scope.identifier else const.BUSDOX_DOCID_QNS
        )
        fields["process_identifier"] = process_scope.instance_identifier.value
        return fields

    @classmethod
    def get_standard_business_document(
        cls,
        builder_args: PeppolAS4MessageBuilderArgs,
        references: AS4References,
    ) -> sbdh.StandardBusinessDocument:
        doc_id = builder_args.document_type_identifier
        document_identification = sbdh.DocumentIdentification(
            standard=sbdh.Standard(value=doc_id.root_element_namespace),
            type_version=sbdh.TypeVersion(value=doc_id.version),
            instance_identifier=sbdh.InstanceIdentifier(
                value=builder_args.document_identification_instance_identifier
            ),
            document_identification_type=sbdh.SBDHType(value=doc_id.root_element_name),
            creation_date_and_time=sbdh.CreationDateAndTime(value=datetime.now(UTC)),
        )
        business_scope = sbdh.BusinessScope(
            scopes=[
                sbdh.Scope(
                    scope_type=sbdh.SBDHType(value="DOCUMENTID"),
                    instance_identifier=sbdh.InstanceIdentifier(value=doc_id.identifier_value),
                    identifier=sbdh.ScopeIdentifier(value=doc_id.scheme),
                ),
                sbdh.Scope(
                    scope_type=sbdh.SBDHType(value="PROCESSID"),
                    instance_identifier=sbdh.InstanceIdentifier(value=builder_args.process_identifier),
                    identifier=sbdh.ScopeIdentifier(value=const.CENBII_PROCID_UBL),
                ),
                sbdh.Scope(
                    scope_type=sbdh.SBDHType(value="COUNTRY_C1"),
                    instance_identifier=sbdh.InstanceIdentifier(value=builder_args.c1_country_id),
                ),
            ]
        )
        standard_business_document_header = sbdh.StandardBusinessDocumentHeader(
            header_version=sbdh.HeaderVersion(value="1.0"),
            sender=sbdh.Sender(
                identifier=sbdh.Identifier(value=builder_args.sender, authority=const.ISO6523_ACTOR_ID)
            ),
            receiver=sbdh.Receiver(
                identifier=sbdh.Identifier(value=builder_args.recipient, authority=const.ISO6523_ACTOR_ID)
            ),
            document_identification=document_identification,
            business_scope=business_scope,
        )
        return sbdh.StandardBusinessDocument(standard_business_document_header=standard_business_document_header)

    @classmethod
    def get_user_message(
        cls,
        local_party: AS4InternalParty,
        remote_party: AS4ExternalParty,
        builder_args: PeppolAS4MessageBuilderArgs,
        references: AS4References,
    ) -> UserMessage:
        message_info = MessageInfo(
            timestamp=Timestamp(value=datetime.now(UTC)),
            message_id=MessageId(value=references.message_id),
        )
        party_info = PartyInfo(
            party_to=remote_party.identity.to_party_to(),
            party_from=local_party.identity.to_party_from(),
        )
        document_type_identifier = builder_args.document_type_identifier
        collaboration_info = CollaborationInfo(
            agreement_ref=AgreementRef(value=const.PEPPOL_AP_PROVIDER),
            service=Service(value=builder_args.process_identifier, type_value=const.CENBII_PROCID_UBL),
            action=Action(value=document_type_identifier.action),
            conversation_id=ConversationId(value=references.conversation_id),
        )
        original_sender_property = Property(
            name=const.ORIGINAL_SENDER,
            property_type=const.ISO6523_ACTOR_ID,
            value=builder_args.sender,
        )
        final_recipient_property = Property(
            name=const.FINAL_RECIPIENT,
            property_type=const.ISO6523_ACTOR_ID,
            value=builder_args.recipient,
        )
        part_info_part_properties = PartProperties(
            properties=[
                Property(name="MimeType", value="application/xml"),
                Property(name="CompressionType", value="application/gzip"),
            ]
        )
        message_properties = MessageProperties(properties=[original_sender_property, final_recipient_property])
        part_info: list[PartInfo] = [
            PartInfo(
                part_properties=part_info_part_properties,
                href=f"cid:{attachment_part_id}",
            )
            for attachment_part_id in references.attachment_id_encrypted_data_id_map
        ]
        payload_info = PayloadInfo(part_info=part_info)
        return UserMessage(
            message_info=message_info,
            party_info=party_info,
            collaboration_info=collaboration_info,
            message_properties=message_properties,
            payload_info=payload_info,
        )

    @classmethod
    def get_messaging(
        cls,
        references: AS4References,
        user_message: UserMessage,
    ) -> Messaging:
        return Messaging(
            user_messages=[user_message],
            messaging_id=references.messaging_id,
            w3_org_2003_05_soap_envelope_must_understand=True,
        )

    @classmethod
    def get_messaging_digest_reference(
        cls,
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
    def get_body_digest_reference(cls, references: AS4References, body: Body) -> DsigReference:
        body_clark_name = "{http://www.w3.org/2003/05/soap-envelope}Body"
        return DsigReference.for_element(
            uri=f"#{references.body_id}",
            element=body.dump_to_xml(body_clark_name),
            digest_algorithm=DigestAlgorithm.SHA256,
        )

    @classmethod
    def get_payload_digest_reference(cls, attachment_id: str, compressed_payload: bytes) -> DsigReference:
        """AS4 5.1.5 signs every payload MIME part with the Attachment-Content-Only transform, 3.1 post-compression."""
        return DsigReference.for_bytes(
            uri=f"cid:{attachment_id}",
            content=compressed_payload,
            digest_algorithm=DigestAlgorithm.SHA256,
            transform_algorithm=TransformAlgorithm.ATTACHMENT_CONTENT_SIGNATURE,
        )

    @classmethod
    def get_signed_info(
        cls,
        references: AS4References,
        messaging: Messaging,
        body: Body,
        compressed_payloads: dict[str, bytes],
    ) -> SignedInfo:

        messaging_digest_reference = cls.get_messaging_digest_reference(references, messaging)
        return SignedInfo(
            references=[
                messaging_digest_reference,
                cls.get_body_digest_reference(references, body),
                *(
                    cls.get_payload_digest_reference(attachment_id, compressed_payload)
                    for attachment_id, compressed_payload in compressed_payloads.items()
                ),
            ],
            canonicalization_method=CanonicalizationMethod(algorithm=const.XML_EXC_C14N),
            signature_method=SignatureMethod(algorithm=const.DSIG_RSA_SHA256),
        )

    @classmethod
    def get_remote_binary_security_token(
        cls,
        remote_party: AS4ExternalParty,
        references: AS4References,
    ) -> BinarySecurityToken:
        return BinarySecurityToken(
            encoding_type=const.BASE_64_BINARY,
            value_type=const.X509_V3,
            bst_id=references.encrypted_key_bst_id,
            value=base64.b64encode(remote_party.credentials.certificate.public_bytes(serialization.Encoding.DER)),
        )

    @classmethod
    def get_local_binary_security_token(
        cls,
        local_party: AS4InternalParty,
        references: AS4References,
    ) -> BinarySecurityToken:
        return BinarySecurityToken(
            encoding_type=const.BASE_64_BINARY,
            value_type=const.X509_V3,
            bst_id=references.signature_bst_id,
            value=base64.b64encode(local_party.credentials.certificate.public_bytes(serialization.Encoding.DER)),
        )

    @classmethod
    def get_encrypted_key(
        cls,
        references: AS4References,
        encrypted_session_key: bytes,
    ) -> EncryptedKey:

        encryption_method = EncryptionMethod(
            algorithm=EncryptionAlgorithm.RSA_OAEP,
            mgf=MGF(algorithm=const.MGF1_SHA256),
            digest_method=DigestMethod(algorithm=const.XMLENC_SHA256),
        )
        reference_list = ReferenceList(
            data_reference=[
                XencReference(uri=f"#{encrypted_data_id}")
                for encrypted_data_id in references.attachment_id_encrypted_data_id_map.values()
            ]
        )
        encrypted_key = EncryptedKey(
            encrypted_type_id=references.encrypted_key_id,
            encryption_method=encryption_method,
            reference_list=reference_list,
            key_info=KeyInfo(
                security_token_reference=[
                    SecurityTokenReference(
                        reference=WsseReference(
                            uri=f"#{references.encrypted_key_bst_id}",
                            value_type=const.X509_V3,
                        )
                    )
                ]
            ),
            cipher_data=CipherData(
                cipher_value=CipherValue(
                    value=base64.b64encode(encrypted_session_key),
                ),
            ),
            type_value="",
            mime_type="",
            encoding="",
        )
        return encrypted_key

    @classmethod
    def get_encrypted_data(
        cls,
        references: AS4References,
    ) -> list[EncryptedType]:
        encrypted_data_list: list[EncryptedType] = []
        for attachment_part_id, encrypted_data_id in references.attachment_id_encrypted_data_id_map.items():
            cipher_data = CipherData(
                cipher_value=None,
                cipher_reference=CipherReference(
                    uri=f"cid:{attachment_part_id}",
                    transforms=XencTransforms(
                        transforms=[DsigTransform(algorithm=const.ATTACHMENT_CIPHERTEXT_TRANSFORM)]
                    ),
                ),
            )
            encrypted_data = EncryptedType(
                encrypted_type_id=encrypted_data_id,
                encryption_method=EncryptionMethod(algorithm=EncryptionAlgorithm.AES128_GCM),
                mime_type="application/gzip",
                type_value=const.SWA_PROFILE_ATTACHMENT_CONTENT_ONLY,
                key_info=KeyInfo(
                    security_token_reference=[
                        SecurityTokenReference(
                            reference=WsseReference(
                                uri=f"#{references.encrypted_key_id}",
                            ),
                            token_type=const.ENCRYPTED_KEY_TOKEN_TYPE,
                        )
                    ]
                ),
                cipher_data=cipher_data,
            )
            encrypted_data_list.append(encrypted_data)
        return encrypted_data_list

    @classmethod
    def get_signature(
        cls,
        local_party: AS4InternalParty,
        builder_args: PeppolAS4MessageBuilderArgs,
        references: AS4References,
        signed_info: SignedInfo,
    ) -> Signature:
        signed_info.etree_element = signed_info.dump_to_xml(
            "{http://www.w3.org/2000/09/xmldsig#}SignedInfo",
            namespaces=builder_args.namespace_map,
        )
        signed_info_canonicalised = signed_info.signed_info_canonicalized
        signature_bytes = local_party.credentials.private_key.sign(
            signed_info_canonicalised, padding.PKCS1v15(), hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")
        return Signature(
            signature_id=references.signature_id,
            key_info=KeyInfo(
                key_info_id=references.key_info_id,
                security_token_reference=[
                    SecurityTokenReference(
                        security_token_reference_id=references.signature_security_token_reference_id,
                        reference=WsseReference(
                            uri=f"#{references.signature_bst_id}",
                            value_type=(
                                "http://docs.oasis-open.org/wss/2004/01/"
                                "oasis-200401-wss-x509-token-profile-1.0#X509v3"
                            ),
                        ),
                    ),
                ],
            ),
            signature_value=SignatureValue(value=signature_b64),
            signed_info=signed_info,
        )

    @classmethod
    def get_soap_envelope(
        cls,
        local_party: AS4InternalParty,
        remote_party: AS4ExternalParty,
        builder_args: PeppolAS4MessageBuilderArgs,
        references: AS4References,
        encrypted_session_key: bytes,
        compressed_payloads: dict[str, bytes],
    ) -> Envelope:
        user_message = cls.get_user_message(
            local_party=local_party,
            remote_party=remote_party,
            builder_args=builder_args,
            references=references,
        )
        messaging = cls.get_messaging(
            references=references,
            user_message=user_message,
        )
        body = Body(body_id=references.body_id)
        signed_info = cls.get_signed_info(
            references=references,
            messaging=messaging,
            body=body,
            compressed_payloads=compressed_payloads,
        )
        signature = cls.get_signature(
            local_party=local_party,
            builder_args=builder_args,
            references=references,
            signed_info=signed_info,
        )
        return Envelope(
            header=Header(
                security=Security(
                    binary_security_tokens=[
                        cls.get_remote_binary_security_token(remote_party, references),
                        cls.get_local_binary_security_token(local_party, references),
                    ],
                    encrypted_key=cls.get_encrypted_key(references, encrypted_session_key),
                    encrypted_data=cls.get_encrypted_data(references),
                    signature=signature,
                ),
                messaging=messaging,
            ),
            body=body,
        )

    @classmethod
    def build_message(
        cls,
        payload: bytes,
        *,
        local_party: AS4InternalParty,
        remote_party: AS4ExternalParty,
        builder_args: PeppolAS4MessageBuilderArgs,
        references: AS4References,
    ) -> Self:
        sbd_object = cls.get_standard_business_document(builder_args, references)
        sbd_element = sbd_object.dump_to_xml(
            "{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}StandardBusinessDocument"
        )
        sbd_element.append(parse_xml(payload))
        payload = etree.tostring(sbd_element)
        compressed_payload = gzip.compress(payload)
        session_key, encrypted_payload = CipherHandler.encrypt_payload(compressed_payload)
        encrypted_session_key = remote_party.credentials.rsa_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=b"",
            ),
        )
        attachment_id, _encrypted_data_id = references.encrypted_data_attachment_mapping()
        soap_envelope = cls.get_soap_envelope(
            local_party,
            remote_party,
            builder_args,
            references,
            encrypted_session_key,
            compressed_payloads={attachment_id: compressed_payload},
        )

        return cls(
            soap_envelope=soap_envelope,
            message_id=references.message_id,
            messaging_id=references.messaging_id,
            mime_attachments={attachment_id: encrypted_payload},
            decrypted_data={attachment_id: payload},
            sender=builder_args.sender,
            recipient=builder_args.recipient,
            document_type_identifier_value=builder_args.document_type_identifier.identifier_value,
            document_type_identifier_scheme=builder_args.document_type_identifier.scheme,
            process_identifier=builder_args.process_identifier,
        )
