"""SecurityPolicy.sign_required and encrypt_required were declared and never read. These prove they gate."""

import re

import pytest
from lxml import etree
from as4.core.context import SecurityPolicy
from as4.core.message import AS4Message
from as4.core.trust import pinned_certificates
from as4.utils.mime_handler import MIMEHandler
from tests.assets.test_credentials import test_sender

NAMESPACES = {
    "S12": "http://www.w3.org/2003/05/soap-envelope",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "enc": "http://www.w3.org/2001/04/xmlenc#",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
}


def parts(headers, body):
    soap_part, encrypted_part = MIMEHandler.parse(MIMEHandler.payload_from_request(headers, body))
    return (
        etree.fromstring(soap_part.get_payload(decode=True)),
        {MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )


def without(envelope, xpath):
    element = envelope.xpath(xpath, namespaces=NAMESPACES)[0]
    element.getparent().remove(element)
    return envelope


def parsed(envelope, attachments, policy, receiving_party):
    from as4.core.context import AS4ParseContext

    return AS4Message.parse(
        parse_context=AS4ParseContext(local_party=receiving_party, security_policy=policy),
        soap_bytes=etree.tostring(envelope),
        mime_attachments=attachments,
    )


@pytest.fixture
def unsigned(local_party, remote_party, send):
    envelope, attachments = parts(*send(local_party, remote_party))
    return without(envelope, "//wsse:Security/ds:Signature"), attachments


@pytest.fixture
def unencrypted(local_party, remote_party, send):
    envelope, attachments = parts(*send(local_party, remote_party))
    return without(envelope, "//wsse:Security/enc:EncryptedKey"), attachments


def test_an_unsigned_message_is_refused_when_signing_is_required(unsigned, receiving_party):
    envelope, attachments = unsigned
    policy = SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate))

    message = parsed(envelope, attachments, policy, receiving_party)

    assert message.parse_error is not None
    assert message.parse_error.error_code == "EBMS:0103"
    assert "requires a signature" in message.parse_error.detail


def test_an_unsigned_message_is_accepted_when_signing_is_not_required(unsigned, receiving_party):
    envelope, attachments = unsigned
    policy = SecurityPolicy(sign_required=False, verify_digests=False)

    message = parsed(envelope, attachments, policy, receiving_party)

    assert message.parse_error is None
    assert message.signer_certificate is None
    assert message.signed_references == []
    assert message.decrypted_data


def test_an_unencrypted_message_is_refused_when_encryption_is_required(unencrypted, receiving_party):
    envelope, attachments = unencrypted
    policy = SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate), verify_digests=False)

    message = parsed(envelope, attachments, policy, receiving_party)

    assert message.parse_error is not None
    assert message.parse_error.error_code == "EBMS:0103"
    assert "requires encryption" in message.parse_error.detail


def test_an_unencrypted_message_is_accepted_when_encryption_is_not_required(unencrypted, receiving_party):
    envelope, attachments = unencrypted
    policy = SecurityPolicy(
        encrypt_required=False,
        verify_digests=False,
        signer_resolver=pinned_certificates(test_sender.certificate),
    )

    message = parsed(envelope, attachments, policy, receiving_party)

    assert message.parse_error is None
    assert message.signer_certificate == test_sender.certificate
    assert message.decrypted_data == {}


def test_a_signature_is_still_verified_when_encryption_is_not_required(unencrypted, receiving_party):
    """Relaxing one requirement must not relax the other."""
    envelope, attachments = unencrypted
    signature_value = envelope.xpath("//ds:SignatureValue", namespaces=NAMESPACES)[0]
    signature_value.text = re.sub(r"[A-Za-z]", "A", signature_value.text)
    policy = SecurityPolicy(
        encrypt_required=False,
        verify_digests=False,
        signer_resolver=pinned_certificates(test_sender.certificate),
    )

    message = parsed(envelope, attachments, policy, receiving_party)

    assert message.parse_error is not None
    assert message.parse_error.error_code == "EBMS:0101"


def test_a_signature_is_verified_even_when_signing_is_not_required(local_party, remote_party, receiving_party, send):
    """sign_required only decides whether a signature must be present, never whether to check one."""
    envelope, attachments = parts(*send(local_party, remote_party))
    signature_value = envelope.xpath("//ds:SignatureValue", namespaces=NAMESPACES)[0]
    signature_value.text = re.sub(r"[A-Za-z]", "A", signature_value.text)
    policy = SecurityPolicy(
        sign_required=False,
        verify_digests=False,
        signer_resolver=pinned_certificates(test_sender.certificate),
    )

    message = parsed(envelope, attachments, policy, receiving_party)

    assert message.parse_error is not None
    assert message.parse_error.error_code == "EBMS:0101"
