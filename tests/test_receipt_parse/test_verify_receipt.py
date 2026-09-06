import base64

import pytest
from lxml import etree
from as4 import const
from as4.core.common import (
    AS4BaseCredentials,
    AS4ExternalParty,
    AS4InternalCredentials,
    AS4InternalParty,
    AS4PartyIdentity,
)
from as4.core.context import SecurityPolicy
from as4.core.receipt import AS4Receipt
from as4.errors import ReceiptVerificationError
from as4.models.dsig.reference import DigestAlgorithm
from as4.models.dsig.reference import Reference as DsigReference
from as4.models.dsig.signature import CanonicalizationMethod, SignatureMethod, SignedInfo
from as4.core.trust import pinned_certificates
from as4.profiles.peppol.profile import build_peppol_message, parse_peppol_message, parse_peppol_receipt
from tests.assets.test_credentials import test_receiver, test_sender

SENDING_AP_ID = "PTE000001"
RECEIVING_AP_ID = "PTE000002"
DOCUMENT_TYPE_IDENTIFIER = (
    "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice"
    "##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1"
)
NAMESPACES = {
    "S12": "http://www.w3.org/2003/05/soap-envelope",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "eb3": "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/",
}


@pytest.fixture
def sent_message():
    return build_peppol_message(
        payload=b'<Invoice xmlns="urn:test">payload</Invoice>',
        local_party=AS4InternalParty(
            identity=AS4PartyIdentity(party_id=SENDING_AP_ID, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
            credentials=AS4InternalCredentials(
                certificate=test_sender.certificate,
                private_key=test_sender.private_key,
            ),
        ),
        remote_party=AS4ExternalParty(
            identity=AS4PartyIdentity(party_id=RECEIVING_AP_ID, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
            credentials=AS4BaseCredentials(certificate=test_receiver.certificate),
        ),
        sender="9932:2222222222",
        recipient="9932:3333333333",
        document_type_identifier_scheme="busdox-docid-qns",
        document_type_identifier_value=DOCUMENT_TYPE_IDENTIFIER,
        process_identifier="urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
        sender_country_id="BE",
    )


def receipt_for(sent_message):
    body, boundary = sent_message.get_request_data()
    exchange = parse_peppol_message(
        request_headers=sent_message.get_http_headers(boundary),
        request_body=body,
        local_party=AS4InternalParty(
            identity=AS4PartyIdentity(party_id=RECEIVING_AP_ID, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
            credentials=AS4InternalCredentials(
                certificate=test_receiver.certificate,
                private_key=test_receiver.private_key,
            ),
        ),
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )
    assert exchange.successful, exchange.error
    _, payload = exchange.build_signal()
    return payload


@pytest.fixture
def receipt_payload(sent_message):
    return receipt_for(sent_message)


def test_a_receipt_from_the_expected_access_point_verifies(receipt_payload, sent_message):
    receipt = parse_peppol_receipt(receipt_payload, test_receiver.certificate)

    assert receipt.success
    receipt.verify_non_repudiation(sent_message.signed_references)


def test_a_receipt_signed_by_another_access_point_is_refused(receipt_payload):
    with pytest.raises(ReceiptVerificationError, match="is signed by"):
        parse_peppol_receipt(receipt_payload, test_sender.certificate)


def test_a_receipt_whose_signature_names_no_security_token_is_refused(receipt_payload):
    envelope = etree.fromstring(receipt_payload)
    key_info = envelope.find(".//ds:Signature/ds:KeyInfo", namespaces=NAMESPACES)
    key_info.remove(key_info[0])

    with pytest.raises(ReceiptVerificationError, match="references no security token"):
        parse_peppol_receipt(etree.tostring(envelope), test_receiver.certificate)


def test_a_tampered_receipt_body_is_refused(receipt_payload):
    envelope = etree.fromstring(receipt_payload)
    timestamp = envelope.find(".//eb3:Timestamp", namespaces=NAMESPACES)
    timestamp.text = "2099-01-01T00:00:00Z"

    with pytest.raises(ReceiptVerificationError, match="does not match the signed element"):
        parse_peppol_receipt(etree.tostring(envelope), test_receiver.certificate)


def test_a_forged_signature_value_is_refused(receipt_payload):
    envelope = etree.fromstring(receipt_payload)
    signature_value = envelope.find(".//ds:SignatureValue", namespaces=NAMESPACES)
    forged = bytearray(base64.b64decode(signature_value.text))
    forged[0] ^= 0xFF
    signature_value.text = base64.b64encode(bytes(forged)).decode()

    with pytest.raises(ReceiptVerificationError, match="does not verify"):
        parse_peppol_receipt(etree.tostring(envelope), test_receiver.certificate)


def test_a_receipt_acknowledging_a_reference_we_did_not_send_is_refused(receipt_payload, sent_message):
    receipt = parse_peppol_receipt(receipt_payload, test_receiver.certificate)
    fewer_sent = sent_message.signed_references[:-1]

    with pytest.raises(ReceiptVerificationError, match="which was not sent"):
        receipt.verify_non_repudiation(fewer_sent)


def test_a_sent_reference_the_receipt_never_acknowledges_is_refused(receipt_payload, sent_message):
    """A duplicate acknowledgement cannot stand in for a missing one, which comparing counts allowed."""
    receipt = parse_peppol_receipt(receipt_payload, test_receiver.certificate)
    sent = sent_message.signed_references
    unacknowledged = sent[0].model_copy(update={"uri": "#never-signed-by-them"})

    with pytest.raises(ReceiptVerificationError, match="does not acknowledge"):
        receipt.verify_non_repudiation([*sent, unacknowledged])


def test_a_receipt_covering_only_the_required_parts_is_accepted(receipt_payload, sent_message):
    """AS4 5.1.8 covers the parts NRR is required for, which need not be everything signed."""
    receipt = parse_peppol_receipt(receipt_payload, test_receiver.certificate)
    sent = sent_message.signed_references
    also_sent = sent[0].model_copy(update={"uri": "#not-covered-by-nrr"})

    receipt.verify_non_repudiation([*sent, also_sent], required_references=sent)


def test_a_receipt_acknowledging_a_different_digest_is_refused(receipt_payload, sent_message):
    receipt = parse_peppol_receipt(receipt_payload, test_receiver.certificate)
    sent = sent_message.signed_references
    sent[0] = sent[0].model_copy(update={"digest_value": base64.b64encode(b"0" * 32).decode()})

    with pytest.raises(ReceiptVerificationError, match="which was not sent"):
        receipt.verify_non_repudiation(sent)


def test_a_receipt_naming_no_message_is_refused(receipt_payload):
    envelope = etree.fromstring(receipt_payload)
    ref_to_message_id = envelope.find(".//eb3:RefToMessageId", namespaces=NAMESPACES)
    ref_to_message_id.getparent().remove(ref_to_message_id)

    with pytest.raises(ReceiptVerificationError, match="names no eb:RefToMessageId"):
        parse_peppol_receipt(etree.tostring(envelope), test_receiver.certificate)


def test_requiring_no_references_is_refused(receipt_payload, sent_message):
    """An explicit empty required_references would accept any receipt, including an empty one."""
    receipt = parse_peppol_receipt(receipt_payload, test_receiver.certificate)

    with pytest.raises(ReceiptVerificationError, match="would prove nothing"):
        receipt.verify_non_repudiation(sent_message.signed_references, [])


def test_a_receipt_whose_signature_skips_the_messaging_block_is_refused(sent_message, monkeypatch):
    """AS4 5.1.4 (b): the signature must cover eb:Messaging, which is where the receipt's content lives."""

    def only_the_body(cls, builder_args, references, messaging, body):
        element = body.dump_to_xml("{http://www.w3.org/2003/05/soap-envelope}Body")
        return SignedInfo(
            references=[DsigReference.for_element(f"#{references.body_id}", element, DigestAlgorithm.SHA256)],
            canonicalization_method=CanonicalizationMethod(algorithm=const.XML_EXC_C14N),
            signature_method=SignatureMethod(algorithm=const.DSIG_RSA_SHA256),
        )

    monkeypatch.setattr(AS4Receipt, "get_signed_info", classmethod(only_the_body))

    with pytest.raises(ReceiptVerificationError, match="does not cover eb:Messaging"):
        parse_peppol_receipt(receipt_for(sent_message), test_receiver.certificate)


@pytest.mark.parametrize("payload", [b"<html>502 Bad Gateway</html>", b"not xml at all"], ids=["html", "text"])
def test_a_response_that_is_not_a_signal_is_refused(payload):
    with pytest.raises(ReceiptVerificationError, match="not a readable ebMS signal"):
        parse_peppol_receipt(payload, test_receiver.certificate)
