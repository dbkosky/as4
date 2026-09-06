import re

from as4.core.context import AS4ParseContext
from as4.core.exchange import ExchangeState
from as4.core.references import AS4References
from as4.profiles.peppol.profile import PeppolAS4Profile
from as4.utils.mime_handler import MIMEHandler
from tests.assets.test_credentials import test_sender


def drop_part(body, content_type):
    boundary = body.split(b"\r\n", 1)[0]
    chunks = body.split(boundary)
    kept = [chunk for chunk in chunks if content_type not in chunk]
    return boundary.join(kept)


def test_a_message_with_no_soap_part_is_answered_with_a_signed_error_signal(
    local_party, remote_party, receiving_party, send, receive, read_signal
):
    headers, body = send(local_party, remote_party)

    receiving = receive(headers, drop_part(body, b"application/soap+xml"), receiving_party)

    assert receiving.state is ExchangeState.REJECTED
    assert receiving.error is not None
    assert receiving.error.error_code == "EBMS:0009"
    payload, signal = read_signal(receiving)
    assert signal.error is not None
    assert signal.error.error_code == receiving.error.error_code
    assert b"ds:SignatureValue" in payload


def test_a_message_with_no_payload_part_is_answered_with_a_signed_error_signal(
    local_party, remote_party, receiving_party, send, receive, read_signal
):
    headers, body = send(local_party, remote_party)

    receiving = receive(headers, drop_part(body, b"application/octet-stream"), receiving_party)

    assert receiving.state is ExchangeState.REJECTED
    assert receiving.error is not None
    assert receiving.error.error_code == "EBMS:0009"
    payload, signal = read_signal(receiving)
    assert signal.error is not None
    assert signal.error.error_code == receiving.error.error_code
    assert b"ds:SignatureValue" in payload


def test_a_soap_part_that_is_not_well_formed_xml_is_answered_with_a_signed_error_signal(
    local_party, remote_party, receiving_party, send, receive, read_signal
):
    headers, body = send(local_party, remote_party)

    receiving = receive(headers, body.replace(b"</S12:Envelope>", b"</S12:Envelo", 1), receiving_party)

    assert receiving.state is ExchangeState.REJECTED
    assert receiving.error is not None
    assert receiving.error.error_code == "EBMS:0009"
    payload, signal = read_signal(receiving)
    assert signal.error is not None
    assert signal.error.error_code == receiving.error.error_code
    assert b"ds:SignatureValue" in payload


def test_an_error_signal_for_a_message_with_no_readable_id_omits_ref_to_message_id(
    local_party, remote_party, receiving_party, send, receive, read_signal
):
    headers, body = send(local_party, remote_party)

    receiving = receive(headers, drop_part(body, b"application/soap+xml"), receiving_party)

    payload, signal = read_signal(receiving)
    assert b"RefToMessageId" not in payload
    assert signal.original_message_id is None


def test_a_party_to_missing_its_role_is_answered_with_a_signed_error_signal(
    local_party, remote_party, receiving_party, send, receive, read_signal
):
    headers, body = send(local_party, remote_party)
    mutated = re.sub(rb"(<eb3:To>.*?)<eb3:Role>.*?</eb3:Role>(.*?</eb3:To>)", rb"\1\2", body, flags=re.DOTALL)
    assert mutated != body

    receiving = receive(headers, mutated, receiving_party)

    assert receiving.state is ExchangeState.REJECTED
    assert receiving.error is not None
    assert receiving.error.error_code == "EBMS:0003"
    payload, signal = read_signal(receiving)
    assert signal.error is not None
    assert signal.error.error_code == receiving.error.error_code
    assert b"ds:SignatureValue" in payload
    # The signal names the message it rejects, which now comes only from the message.
    assert signal.original_message_id == receiving.message.message_id
    assert signal.original_message_id


def test_a_signature_naming_a_token_that_is_not_present_is_refused(
    local_party, remote_party, receiving_party, send, receive
):
    references = AS4References(signature_bst_id="X509-signing")
    headers, body = send(local_party, remote_party, references)

    receiving = receive(headers, body.replace(b"#X509-signing", b"#X509-absent"), receiving_party)

    assert receiving.state is ExchangeState.REJECTED
    assert receiving.error is not None
    assert receiving.error.error_code == "EBMS:0101"


def test_a_token_id_that_prefixes_the_signing_token_is_not_mistaken_for_it(
    local_party, remote_party, receiving_party, send, receive, read_signal
):
    """The encryption token is written first, so a substring match would hand the verifier the wrong certificate."""
    references = AS4References(encrypted_key_bst_id="tok", signature_bst_id="tok-signing")
    headers, body = send(local_party, remote_party, references)

    receiving = receive(headers, body, receiving_party)

    assert receiving.successful, receiving.error
    assert receiving.remote_party is not None
    assert receiving.remote_party.credentials.certificate == test_sender.certificate


def test_a_profile_answers_a_malformed_message_rather_than_raising(receiving_party):
    """The contract lives on AS4Profile, so every caller gets it, not only AS4Exchange."""
    message = PeppolAS4Profile.parse_message(
        b"not a mime message at all",
        AS4ParseContext(local_party=receiving_party),
    )

    assert message.parse_error is not None
    assert message.parse_error.error_code == "EBMS:0009"


def test_unpacking_yields_the_soap_part_and_its_attachments(local_party, remote_party, send):
    """unpack_message is the packaging layer only: it needs no parse context and does no parsing."""
    headers, body = send(local_party, remote_party)

    soap_bytes, mime_attachments = PeppolAS4Profile.unpack_message(MIMEHandler.payload_from_request(headers, body))

    assert soap_bytes.startswith(b"<S12:Envelope")
    assert len(mime_attachments) == 1
