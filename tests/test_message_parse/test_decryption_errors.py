import base64

import pytest
from as4 import const
from as4.core.common import AS4InternalCredentials, AS4InternalParty, AS4PartyIdentity
from as4.core.context import SecurityPolicy
from as4.core.trust import pinned_certificates
from as4.profiles.peppol.profile import (
    build_peppol_message,
    create_peppol_external_party,
    create_peppol_internal_party,
    parse_peppol_message,
)
from tests.assets.test_credentials import test_receiver, test_sender

SENDING_AP_ID = "PTE000001"
RECEIVING_AP_ID = "PTE000002"
DOCUMENT_TYPE_IDENTIFIER = (
    "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice"
    "##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1"
)


@pytest.fixture
def built_message():
    return build_peppol_message(
        payload=b'<Invoice xmlns="urn:test">payload</Invoice>',
        local_party=create_peppol_internal_party(SENDING_AP_ID, test_sender.certificate, test_sender.private_key),
        remote_party=create_peppol_external_party(RECEIVING_AP_ID, test_receiver.certificate),
        sender="0208:2222222222",
        recipient="0208:3333333333",
        document_type_identifier_scheme="busdox-docid-qns",
        document_type_identifier_value=DOCUMENT_TYPE_IDENTIFIER,
        process_identifier="urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
        sender_country_id="BE",
    )


@pytest.fixture
def internal_receiver():
    return AS4InternalParty(
        identity=AS4PartyIdentity(party_id=RECEIVING_AP_ID, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
        credentials=AS4InternalCredentials(
            certificate=test_receiver.certificate,
            private_key=test_receiver.private_key,
        ),
    )


def parse(message, internal_receiver):
    body, boundary = message.get_request_data()
    return parse_peppol_message(
        request_headers=message.get_http_headers(boundary),
        request_body=body,
        local_party=internal_receiver,
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )


def only_attachment(message):
    attachment_id, *_ = message.mime_attachments
    return attachment_id


def test_corrupted_attachment_reports_failed_decryption(built_message, internal_receiver):
    """AES-GCM rejects the tag; before this the InvalidTag escaped parse entirely."""
    attachment_id = only_attachment(built_message)
    ciphertext = bytearray(built_message.mime_attachments[attachment_id])
    ciphertext[-1] ^= 0x01
    built_message.mime_attachments[attachment_id] = bytes(ciphertext)

    parse_result = parse(built_message, internal_receiver)

    assert not parse_result.successful
    assert parse_result.error.error_code == "EBMS:0102"


def test_corrupted_session_key_reports_failed_decryption(built_message, internal_receiver):
    encrypted_key = built_message.soap_envelope.header.security.encrypted_key
    session_key_bytes = bytearray(base64.b64decode(encrypted_key.cipher_data.cipher_value.value))
    session_key_bytes[-1] ^= 0x01
    encrypted_key.cipher_data.cipher_value.value = base64.b64encode(bytes(session_key_bytes)).decode("ascii")

    parse_result = parse(built_message, internal_receiver)

    assert not parse_result.successful
    assert parse_result.error.error_code == "EBMS:0102"


def test_decryption_failures_are_indistinguishable(built_message, internal_receiver):
    """Distinguishable RSA and AES failures are a padding oracle, so both report one detail."""
    attachment_id = only_attachment(built_message)
    ciphertext = bytearray(built_message.mime_attachments[attachment_id])
    ciphertext[-1] ^= 0x01
    built_message.mime_attachments[attachment_id] = bytes(ciphertext)
    corrupted_attachment = parse(built_message, internal_receiver)

    encrypted_key = built_message.soap_envelope.header.security.encrypted_key
    session_key_bytes = bytearray(base64.b64decode(encrypted_key.cipher_data.cipher_value.value))
    session_key_bytes[-1] ^= 0x01
    encrypted_key.cipher_data.cipher_value.value = base64.b64encode(bytes(session_key_bytes)).decode("ascii")
    corrupted_session_key = parse(built_message, internal_receiver)

    assert corrupted_attachment.error.error_detail.value == corrupted_session_key.error.error_detail.value


def test_cipher_reference_to_a_missing_attachment_reports_failed_decryption(built_message, internal_receiver):
    """Previously a KeyError on mime_attachments, which escaped parse the same way InvalidTag did."""
    encrypted_data, *_ = built_message.soap_envelope.header.security.encrypted_data
    encrypted_data.cipher_data.cipher_reference.uri = "cid:not-an-attachment"

    parse_result = parse(built_message, internal_receiver)

    assert not parse_result.successful
    assert parse_result.error.error_code == "EBMS:0102"


def test_unsupported_encryption_algorithm_reports_policy_noncompliance(built_message, internal_receiver):
    """Previously the match fell through, leaving the payload undecrypted and the message accepted."""
    encrypted_data, *_ = built_message.soap_envelope.header.security.encrypted_data
    encrypted_data.encryption_method.algorithm = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"

    parse_result = parse(built_message, internal_receiver)

    assert not parse_result.successful
    assert parse_result.error.error_code == "EBMS:0103"
