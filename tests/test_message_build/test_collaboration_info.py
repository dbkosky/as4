"""Peppol AS4 4.6: eb:Service is the process identifier and eb:Action is the scheme-qualified document type."""

from lxml import etree
from as4.core.common import AS4BaseCredentials, AS4ExternalParty, AS4InternalCredentials, AS4InternalParty
from as4.core.common import AS4PartyIdentity
from as4.profiles.peppol.profile import build_peppol_message
from tests.assets.test_credentials import test_receiver, test_sender
from as4.core.common import AS4LocalPrivateKey

NAMESPACES = {"eb3": "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"}
DOCUMENT_TYPE_IDENTIFIER = (
    "urn:oasis:names:specification:ubl:schema:xsd:Order-2::Order" "##urn:fdc:peppol.eu:poacc:trns:order:3::2.1"
)
PROCESS_IDENTIFIER = "urn:fdc:peppol.eu:poacc:bis:ordering:3"


def build(**overrides):
    return build_peppol_message(
        payload=b'<Order xmlns="urn:test"/>',
        local_party=AS4InternalParty(
            identity=AS4PartyIdentity(party_id="PTE000001", party_type="urn:fdc:peppol.eu:2017:identifiers:ap"),
            credentials=AS4InternalCredentials(
                certificate=test_sender.certificate, private_key=AS4LocalPrivateKey(test_sender.private_key)
            ),
        ),
        remote_party=AS4ExternalParty(
            identity=AS4PartyIdentity(party_id="PTE000002", party_type="urn:fdc:peppol.eu:2017:identifiers:ap"),
            credentials=AS4BaseCredentials(certificate=test_receiver.certificate),
        ),
        sender="0208:2222222222",
        recipient="0208:3333333333",
        document_type_identifier_scheme="busdox-docid-qns",
        document_type_identifier_value=DOCUMENT_TYPE_IDENTIFIER,
        process_identifier=PROCESS_IDENTIFIER,
        sender_country_id="BE",
        **overrides,
    )


def collaboration_info(message):
    return etree.fromstring(message.soap_envelope_xml).find(".//eb3:CollaborationInfo", namespaces=NAMESPACES)


def test_the_service_and_action_name_the_document_being_sent():
    info = collaboration_info(build())
    service = info.find("eb3:Service", namespaces=NAMESPACES)

    assert (service.text, service.get("type")) == (PROCESS_IDENTIFIER, "cenbii-procid-ubl")
    assert info.findtext("eb3:Action", namespaces=NAMESPACES) == f"busdox-docid-qns::{DOCUMENT_TYPE_IDENTIFIER}"
