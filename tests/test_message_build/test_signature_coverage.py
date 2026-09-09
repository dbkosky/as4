from as4 import const
import pytest
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
from as4.core.common import AS4LocalPrivateKey

SENDING_AP_ID = "0208:0000000000"
RECEIVING_AP_ID = "0208:1111111111"
DOCUMENT_TYPE_IDENTIFIER = (
    "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice"
    "##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1"
)


@pytest.fixture
def built_message():
    return build_peppol_message(
        payload=b'<Invoice xmlns="urn:test">payload</Invoice>',
        local_party=create_peppol_internal_party(
            SENDING_AP_ID, test_sender.certificate, AS4LocalPrivateKey(test_sender.private_key)
        ),
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
            private_key=AS4LocalPrivateKey(test_receiver.private_key),
        ),
    )


def references_by_uri(message):
    signature = message.soap_envelope.header.security.signature
    return {reference.uri: reference for reference in signature.signed_info.references}


def test_signature_covers_messaging_body_and_payload(built_message):
    """AS4 5.1.4 and 5.1.5: the eb:Messaging block, the SOAP Body and every payload part are signed."""
    messaging_id = built_message.soap_envelope.header.messaging.messaging_id
    body_id = built_message.soap_envelope.body.body_id
    attachment_id, *rest = built_message.mime_attachments

    assert not rest
    assert set(references_by_uri(built_message)) == {f"#{messaging_id}", f"#{body_id}", f"cid:{attachment_id}"}


def test_payload_reference_uses_the_attachment_content_transform(built_message):
    attachment_id, *_ = built_message.mime_attachments
    transform, *rest = references_by_uri(built_message)[f"cid:{attachment_id}"].transforms.transforms

    assert not rest
    assert transform.algorithm == const.SWA_ATTACHMENT_CONTENT_SIGNATURE_TRANSFORM


def test_payload_digest_does_not_cover_the_ciphertext(built_message):
    """AS4 3.1 compresses, then signs, then encrypts: the digest binds neither the raw payload nor the ciphertext."""
    attachment_id, *_ = built_message.mime_attachments
    reference = references_by_uri(built_message)[f"cid:{attachment_id}"]

    assert not reference.digest_matches_bytes(built_message.mime_attachments[attachment_id])
    assert not reference.digest_matches_bytes(built_message.decrypted_data[attachment_id])


def test_built_message_round_trips_through_parse(built_message, internal_receiver):
    """Everything the builder signs is what the parser verifies, payload digest included."""
    body, boundary = built_message.get_request_data()

    parse_result = parse_peppol_message(
        request_headers=built_message.get_http_headers(boundary),
        request_body=body,
        local_party=internal_receiver,
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )

    assert parse_result.successful, parse_result.error
