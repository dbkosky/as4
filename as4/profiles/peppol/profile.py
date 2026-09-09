from typing import Callable, Sequence
from uuid import uuid4

from cryptography import x509
from cryptography.x509.oid import NameOID
from as4 import const

from as4.core.common import (
    AS4BaseCredentials,
    AS4ExternalParty,
    AS4InternalCredentials,
    AS4InternalParty,
    AS4PartyIdentity,
    AS4PrivateKey,
)
from as4.core.context import ParticipantAcceptor, SecurityPolicy, SignerResolver
from as4.errors import PayloadPartNotFoundException, SoapPartNotFoundException
from as4.core.exchange import AS4Exchange, AS4ReceivingExchange, AS4SendingExchange
from as4.core.profiles import AS4Profile
from as4.core.references import AS4References
from as4.core.trust import certificate_chain
from as4.errors import UntrustedSignerError
from as4.models.ebms.user_message import PartyFrom
from as4.profiles.peppol.document_identifier import BusdoxDocidQnsDocumentIdentifier
from as4.profiles.peppol.message import PeppolAS4Message, PeppolAS4MessageBuilderArgs
from as4.profiles.peppol.pki import (
    PEPPOL_AP_CA_G3,
    PEPPOL_AP_TEST_CA_G3,
    PEPPOL_ROOT_CA_G3,
    PEPPOL_ROOT_TEST_CA_G3,
)
from as4.profiles.peppol.receipt import PeppolAS4Receipt
from as4.utils.mime_handler import MIMEHandler


DEFAULT_SECURITY_POLICY = SecurityPolicy()

PEPPOL_CHAIN_DEPTH = 3


def certificate_names_the_sender(resolver: SignerResolver) -> SignerResolver:
    def resolve(party_from: PartyFrom, embedded: x509.Certificate | None) -> x509.Certificate:
        certificate = resolver(party_from, embedded)
        claimed = party_from.party_id.value
        common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not any(name.value == claimed for name in common_names):
            raise UntrustedSignerError(f"The signing certificate does not name {claimed!r} as its subject")
        return certificate

    return resolve


def peppol_security_policy(
    *anchors: x509.Certificate,
    intermediates: Sequence[x509.Certificate] = (),
    revoked: Callable[[x509.Certificate], bool] | None = None,
) -> SecurityPolicy:
    """Peppol trusts any AP certificate chaining to its PKI, so anchors come from the caller's trust store."""
    return SecurityPolicy(
        signer_resolver=certificate_names_the_sender(
            certificate_chain(
                *anchors,
                intermediates=intermediates,
                revoked=revoked,
                maximum_depth=PEPPOL_CHAIN_DEPTH,
            )
        )
    )


PEPPOL_PROD_SECURITY_POLICY = peppol_security_policy(PEPPOL_ROOT_CA_G3, intermediates=[PEPPOL_AP_CA_G3])

PEPPOL_TEST_SECURITY_POLICY = peppol_security_policy(PEPPOL_ROOT_TEST_CA_G3, intermediates=[PEPPOL_AP_TEST_CA_G3])

PeppolExchange = AS4Exchange[PeppolAS4Message, PeppolAS4Receipt, PeppolAS4MessageBuilderArgs]
PeppolReceivingExchange = AS4ReceivingExchange[PeppolAS4Message, PeppolAS4Receipt, PeppolAS4MessageBuilderArgs]
PeppolSendingExchange = AS4SendingExchange[PeppolAS4Message, PeppolAS4Receipt, PeppolAS4MessageBuilderArgs]


class PeppolAS4Profile(AS4Profile[PeppolAS4Message, PeppolAS4Receipt, PeppolAS4MessageBuilderArgs]):

    @classmethod
    def get_profile_name(cls) -> str:
        return "peppol"

    @classmethod
    def message_class(cls) -> type[PeppolAS4Message]:
        return PeppolAS4Message

    @classmethod
    def receipt_class(cls) -> type[PeppolAS4Receipt]:
        return PeppolAS4Receipt

    @classmethod
    def unpack_message(cls, payload: bytes) -> tuple[bytes, dict[str, bytes]]:
        soap_part, encrypted_part = MIMEHandler.parse(payload)
        soap_data = soap_part.get_payload(decode=True)
        if not isinstance(soap_data, bytes):
            raise SoapPartNotFoundException(detail="SOAP part carries no decodable content")

        encrypted_part_bytes = encrypted_part.get_payload(decode=True)
        encrypted_part_content_id = MIMEHandler.get_content_id(encrypted_part)
        if not isinstance(encrypted_part_bytes, bytes):
            raise PayloadPartNotFoundException(detail="Payload part carries no decodable content")
        if not encrypted_part_content_id:
            raise PayloadPartNotFoundException(detail="Payload part carries no Content-ID header")
        return soap_data, {encrypted_part_content_id: encrypted_part_bytes}

    @classmethod
    def parse_receipt(cls, payload: bytes, expected_signer: x509.Certificate) -> PeppolAS4Receipt:
        return PeppolAS4Receipt.parse(payload, expected_signer)

    @classmethod
    def build_message(
        cls,
        payload: bytes,
        *,
        local_party: AS4InternalParty,
        remote_party: AS4ExternalParty,
        builder_args: PeppolAS4MessageBuilderArgs,
        references: AS4References | None = None,
    ) -> PeppolAS4Message:
        if references is None:
            references = AS4References()
        return PeppolAS4Message.build_message(
            payload=payload,
            local_party=local_party,
            remote_party=remote_party,
            builder_args=builder_args,
            references=references,
        )


def create_peppol_internal_party(
    party_id: str,
    certificate: x509.Certificate,
    private_key: AS4PrivateKey,
) -> AS4InternalParty:
    return AS4InternalParty(
        identity=AS4PartyIdentity(party_id=party_id, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
        credentials=AS4InternalCredentials(certificate=certificate, private_key=private_key),
    )


def create_peppol_external_party(
    party_id: str,
    certificate: x509.Certificate,
) -> AS4ExternalParty:
    return AS4ExternalParty(
        identity=AS4PartyIdentity(party_id=party_id, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
        credentials=AS4BaseCredentials(certificate=certificate),
    )


def build_peppol_message(
    payload: bytes,
    *,
    local_party: AS4InternalParty,
    remote_party: AS4ExternalParty,
    sender: str,
    recipient: str,
    document_type_identifier_scheme: str,
    document_type_identifier_value: str,
    process_identifier: str,
    sender_country_id: str,
    document_identification_instance_identifier: str | None = None,
    references: AS4References | None = None,
) -> PeppolAS4Message:
    match document_type_identifier_scheme:
        case "busdox-docid-qns":
            document_type_identifier = BusdoxDocidQnsDocumentIdentifier.from_identifier_value(
                document_type_identifier_value
            )
        case _:
            raise NotImplementedError(f"Unsupported_document_type_identifier_scheme {document_type_identifier_scheme}")

    if document_identification_instance_identifier is None:
        document_identification_instance_identifier = str(uuid4())

    builder_args = PeppolAS4MessageBuilderArgs(
        sender=sender,
        recipient=recipient,
        document_type_identifier=document_type_identifier,
        document_identification_instance_identifier=document_identification_instance_identifier,
        process_identifier=process_identifier,
        c1_country_id=sender_country_id,
    )
    return PeppolAS4Profile.build_message(
        payload,
        local_party=local_party,
        remote_party=remote_party,
        builder_args=builder_args,
        references=references,
    )


def parse_peppol_message(
    request_headers: dict,
    request_body: bytes,
    local_party: AS4InternalParty,
    accept_participant: ParticipantAcceptor | None = None,
    security_policy: SecurityPolicy | None = None,
) -> PeppolReceivingExchange:
    exchange = PeppolReceivingExchange(profile=PeppolAS4Profile, local_party=local_party)
    return exchange.receive(
        request_headers=request_headers,
        request_body=request_body,
        accept_participant=accept_participant,
        security_policy=security_policy or DEFAULT_SECURITY_POLICY,
    )


def parse_peppol_receipt(
    response_payload: bytes,
    expected_signer: x509.Certificate,
) -> PeppolAS4Receipt:
    return PeppolAS4Profile.parse_receipt(response_payload, expected_signer)
