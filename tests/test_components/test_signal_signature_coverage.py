from as4.core.common import (
    AS4InternalCredentials,
    AS4InternalParty,
    AS4PartyIdentity,
    index_elements_by_id,
)
from as4.core.message import AS4Message
from as4.core.receipt import AS4Receipt
from tests.assets.test_credentials import test_receiver

ENVELOPE = "{http://www.w3.org/2003/05/soap-envelope}Envelope"


def coverage_of(receipt):
    element = receipt.require_soap_envelope().dump_to_xml(ENVELOPE)
    signature = receipt.require_soap_envelope().header.security.signature
    return AS4Message.signature_coverage(signature, index_elements_by_id(element), payload_hrefs=set())


LOCAL_PARTY = AS4InternalParty(
    identity=AS4PartyIdentity(party_id="PTE000002", party_type="urn:fdc:peppol.eu:2017:identifiers:ap"),
    credentials=AS4InternalCredentials(certificate=test_receiver.certificate, private_key=test_receiver.private_key),
)


def test_an_error_signal_signs_its_messaging_block_and_its_body():
    receipt = AS4Receipt.create_error_signal(
        error_code="EBMS:0004",
        short_description="Other",
        description="something went wrong",
        severity="failure",
        detail="",
        category="Content",
        referenced_message_id="whatever@peer",
        referenced_messaging_id="peer-msg-1",
        local_party=LOCAL_PARTY,
    )

    assert coverage_of(receipt) == {"messaging", "body", "payloads"}
