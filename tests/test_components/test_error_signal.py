"""ebMS Core 6.2.1: eb:Error/@refToMessageInError names the message in error whenever it is known."""

import pytest
from lxml import etree
from as4.core.common import AS4InternalCredentials, AS4InternalParty, AS4PartyIdentity
from as4.core.receipt import AS4Receipt
from tests.assets.test_credentials import test_receiver
from as4.core.common import AS4LocalPrivateKey

NAMESPACES = {"eb3": "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"}
LOCAL_PARTY = AS4InternalParty(
    identity=AS4PartyIdentity(party_id="PTE000002", party_type="urn:fdc:peppol.eu:2017:identifiers:ap"),
    credentials=AS4InternalCredentials(
        certificate=test_receiver.certificate, private_key=AS4LocalPrivateKey(test_receiver.private_key)
    ),
)


def error_signal(referenced_message_id):
    return AS4Receipt.create_error_signal(
        error_code="EBMS:0004",
        short_description="Other",
        description="something went wrong",
        severity="failure",
        detail="",
        category="Content",
        referenced_message_id=referenced_message_id,
        referenced_messaging_id="peer-msg-1",
        local_party=LOCAL_PARTY,
    )


@pytest.mark.parametrize("message_id", ["whatever@peer", ""], ids=["known", "unknown"])
def test_the_error_names_the_message_in_error_when_it_is_known(message_id):
    envelope = etree.fromstring(error_signal(message_id).get_request_data()[1])
    error = envelope.find(".//eb3:Error", namespaces=NAMESPACES)

    assert error.get("refToMessageInError") == (message_id or None)
    assert envelope.findtext(".//eb3:RefToMessageId", namespaces=NAMESPACES) == (message_id or None)
