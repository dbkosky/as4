import base64

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from lxml import etree
from as4.core.common import AS4BaseCredentials, index_elements_by_id
from as4.core.message import AS4Message
from as4.errors import (
    EncryptedDataNotFoundException,
    SignatureRequiredException,
    UnknownReceiptableError,
)
from as4.models.soap.envelope import Envelope
from tests.assets.test_credentials import test_sender


def test_a_certificate_survives_as_der(local_party, remote_party):
    credentials = AS4BaseCredentials.model_validate_json(remote_party.credentials.model_dump_json())

    assert credentials.certificate == remote_party.credentials.certificate


def test_a_certificate_is_stored_as_the_bytes_that_go_on_the_wire():
    stored = AS4BaseCredentials(certificate=test_sender.certificate).model_dump_json()

    assert base64.b64decode(stored.split('"')[3]) == test_sender.certificate.public_bytes(serialization.Encoding.DER)


def test_a_live_certificate_is_still_accepted():
    assert AS4BaseCredentials(certificate=test_sender.certificate).certificate is test_sender.certificate


def test_a_python_mode_dump_is_left_alone():
    dumped = AS4Message(signer_certificate=test_sender.certificate).model_dump()

    assert isinstance(dumped["signer_certificate"], x509.Certificate)


def test_binary_attachments_survive():
    message = AS4Message(mime_attachments={"cid-1": b"\x00\x01\x02not utf-8\xff"})

    restored = AS4Message.model_validate_json(message.model_dump_json())

    assert restored.mime_attachments == message.mime_attachments


def test_a_parse_error_comes_back_as_its_own_class():
    message = AS4Message(parse_error=SignatureRequiredException())

    restored = AS4Message.model_validate_json(message.model_dump_json())

    assert type(restored.parse_error) is SignatureRequiredException
    assert restored.parse_error.error_code == "EBMS:0103"
    assert restored.parse_error.detail == message.parse_error.detail


def test_an_error_whose_detail_its_constructor_computed_still_returns():
    original = EncryptedDataNotFoundException(encrypted_data_uri="#ED-1")

    restored = AS4Message.model_validate_json(AS4Message(parse_error=original).model_dump_json())

    assert type(restored.parse_error) is EncryptedDataNotFoundException
    assert restored.parse_error.detail == original.detail
    assert "#ED-1" in restored.parse_error.detail


def test_a_parsed_message_survives_whole(send, receive, local_party, remote_party, receiving_party):
    headers, body = send(local_party, remote_party)
    receiving = receive(headers, body, receiving_party)

    restored = AS4Message.model_validate_json(receiving.message.model_dump_json())

    assert restored.message_id == receiving.message.message_id
    assert restored.signer_certificate == receiving.message.signer_certificate
    assert restored.decrypted_data == receiving.message.decrypted_data
    assert restored.soap_envelope_xml == receiving.message.soap_envelope_xml


def test_a_restored_envelope_still_proves_its_own_signature(send, receive, local_party, remote_party, receiving_party):
    headers, body = send(local_party, remote_party)
    receiving = receive(headers, body, receiving_party)

    restored = Envelope.model_validate_json(receiving.message.soap_envelope.model_dump_json())
    element = etree.fromstring(
        etree.tostring(restored.dump_to_xml("{http://www.w3.org/2003/05/soap-envelope}Envelope"))
    )
    elements_by_id = index_elements_by_id(element)

    references = restored.header.security.signature.signed_info.references
    checked = [reference for reference in references if not (reference.uri or "").startswith("cid:")]
    assert checked
    for reference in checked:
        target = elements_by_id.get((reference.uri or "").removeprefix("#"))
        assert target is not None, reference.uri
        assert reference.digest_matches(target), reference.uri


def test_an_unknown_error_class_is_refused():
    with pytest.raises(UnknownReceiptableError, match="renamed or removed"):
        AS4Message.model_validate({"parse_error": {"type": "NoSuchException", "detail": "x"}})
