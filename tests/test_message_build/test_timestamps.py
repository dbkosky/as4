"""ebMS Core 5.2.2.1 requires eb:Timestamp in UTC. The Peppol envelope requires a timezone on CreationDateAndTime."""

from datetime import datetime, timedelta

from lxml import etree
from as4.core.common import AS4BaseCredentials, AS4ExternalParty, AS4InternalCredentials, AS4InternalParty
from as4.core.common import AS4PartyIdentity
from as4.core.receipt import AS4Receipt
from as4.profiles.peppol.profile import build_peppol_message
from tests.assets.test_credentials import test_receiver, test_sender
from as4.core.common import AS4LocalPrivateKey

NAMESPACES = {
    "eb3": "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/",
    "sh": "http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader",
}
LOCAL_PARTY = AS4InternalParty(
    identity=AS4PartyIdentity(party_id="PTE000001", party_type="urn:fdc:peppol.eu:2017:identifiers:ap"),
    credentials=AS4InternalCredentials(
        certificate=test_sender.certificate, private_key=AS4LocalPrivateKey(test_sender.private_key)
    ),
)
REMOTE_PARTY = AS4ExternalParty(
    identity=AS4PartyIdentity(party_id="PTE000002", party_type="urn:fdc:peppol.eu:2017:identifiers:ap"),
    credentials=AS4BaseCredentials(certificate=test_receiver.certificate),
)


def is_utc(text):
    return datetime.fromisoformat(text).utcoffset() == timedelta(0)


def test_a_built_message_stamps_its_header_and_its_envelope_in_utc():
    message = build_peppol_message(
        payload=b'<Invoice xmlns="urn:test"/>',
        local_party=LOCAL_PARTY,
        remote_party=REMOTE_PARTY,
        sender="0208:2222222222",
        recipient="0208:3333333333",
        document_type_identifier_scheme="busdox-docid-qns",
        document_type_identifier_value="urn:test::Invoice##urn:test:customisation::2.1",
        process_identifier="urn:test:process",
        sender_country_id="BE",
    )
    envelope = etree.fromstring(message.soap_envelope_xml)
    (payload,) = message.decrypted_data.values()

    assert is_utc(envelope.findtext(".//eb3:Timestamp", namespaces=NAMESPACES))
    assert is_utc(etree.fromstring(payload).findtext(".//sh:CreationDateAndTime", namespaces=NAMESPACES))


def test_a_signal_stamps_its_header_in_utc():
    receipt = AS4Receipt.create_non_repudiation_receipt(
        referenced_message_id="whatever@peer",
        referenced_messaging_id="peer-msg-1",
        non_repudiated_references=[],
        local_party=LOCAL_PARTY,
    )
    envelope = etree.fromstring(receipt.get_request_data()[1])

    assert is_utc(envelope.findtext(".//eb3:Timestamp", namespaces=NAMESPACES))
