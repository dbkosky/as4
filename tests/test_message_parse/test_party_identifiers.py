import pytest
from as4 import const
from as4.core.common import (
    AS4BaseCredentials,
    AS4ExternalParty,
    AS4InternalCredentials,
    AS4InternalParty,
    AS4PartyIdentity,
)
from as4.core.context import SecurityPolicy
from as4.core.trust import pinned_certificates
from as4.profiles.peppol.profile import build_peppol_message, parse_peppol_message
from tests.assets.test_credentials import test_receiver, test_sender
from as4.core.common import AS4LocalPrivateKey

SENDING_AP_ID = "PTE000001"
RECEIVING_AP_ID = "PTE000002"
DOCUMENT_TYPE_IDENTIFIER = (
    "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice"
    "##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1"
)


def internal_party(party_type):
    return AS4InternalParty(
        identity=AS4PartyIdentity(party_id=SENDING_AP_ID, party_type=party_type),
        credentials=AS4InternalCredentials(
            certificate=test_sender.certificate,
            private_key=AS4LocalPrivateKey(test_sender.private_key),
        ),
    )


def external_party(party_type):
    return AS4ExternalParty(
        identity=AS4PartyIdentity(party_id=RECEIVING_AP_ID, party_type=party_type),
        credentials=AS4BaseCredentials(certificate=test_receiver.certificate),
    )


def build(sender_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE, receiver_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE):
    return build_peppol_message(
        payload=b'<Invoice xmlns="urn:test">payload</Invoice>',
        local_party=internal_party(sender_type),
        remote_party=external_party(receiver_type),
        sender="9932:2222222222",
        recipient="9932:3333333333",
        document_type_identifier_scheme="busdox-docid-qns",
        document_type_identifier_value=DOCUMENT_TYPE_IDENTIFIER,
        process_identifier="urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
        sender_country_id="BE",
    )


def parse(message):
    body, boundary = message.get_request_data()
    return parse_peppol_message(
        request_headers=message.get_http_headers(boundary),
        request_body=body,
        local_party=AS4InternalParty(
            identity=AS4PartyIdentity(party_id=RECEIVING_AP_ID, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
            credentials=AS4InternalCredentials(
                certificate=test_receiver.certificate,
                private_key=AS4LocalPrivateKey(test_receiver.private_key),
            ),
        ),
        security_policy=SecurityPolicy(
            signer_resolver=pinned_certificates(test_sender.certificate),
        ),
    )


def test_a_conformant_message_carries_the_peppol_party_type():
    assert parse(build()).successful


@pytest.mark.parametrize("element,kwargs", [("From", {"sender_type": None}), ("To", {"receiver_type": None})])
def test_a_missing_party_type_is_rejected(element, kwargs):
    result = parse(build(**kwargs))

    assert not result.successful
    error = result.error
    assert error is not None
    assert error.error_code == "EBMS:0004"
    assert f"PartyInfo/{element}/PartyId/@type" in error.error_detail.value


def test_a_party_type_under_another_scheme_is_rejected():
    result = parse(build(sender_type="urn:fdc:peppol.eu:2017:identifiers:AP"))

    assert not result.successful
    assert result.error.error_code == "EBMS:0004"
