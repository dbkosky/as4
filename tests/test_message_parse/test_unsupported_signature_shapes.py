"""A signature this library cannot verify is refused with EBMS:0103, not a crash and not a bare EBMS:0101."""

import base64
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from lxml import etree
from as4.core.context import AS4ParseContext, SecurityPolicy
from as4.core.message import AS4Message
from as4.core.trust import pinned_certificates
from as4.utils.mime_handler import MIMEHandler
from tests.assets.test_credentials import test_sender

NAMESPACES = {
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
}
INCLUSIVE_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"


def parse(headers, body, receiving_party, signer, mutate):
    soap_part, encrypted_part = MIMEHandler.parse(MIMEHandler.payload_from_request(headers, body))
    envelope = etree.fromstring(soap_part.get_payload(decode=True))
    mutate(envelope)
    return AS4Message.parse(
        parse_context=AS4ParseContext(
            local_party=receiving_party,
            security_policy=SecurityPolicy(signer_resolver=pinned_certificates(signer)),
        ),
        soap_bytes=etree.tostring(envelope),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )


def ec_certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PTE000001")])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def test_an_inclusive_canonicalisation_method_is_refused_with_a_signal(
    local_party, remote_party, receiving_party, send
):
    def mutate(envelope):
        envelope.find(".//ds:CanonicalizationMethod", namespaces=NAMESPACES).set("Algorithm", INCLUSIVE_C14N)

    message = parse(*send(local_party, remote_party), receiving_party, test_sender.certificate, mutate)

    assert message.parse_error is not None
    assert message.parse_error.error_code == "EBMS:0103"
    assert INCLUSIVE_C14N in message.parse_error.detail


def test_a_signing_certificate_without_an_rsa_key_is_refused_with_a_signal(
    local_party, remote_party, receiving_party, send
):
    certificate = ec_certificate()

    def mutate(envelope):
        uri = envelope.find(".//ds:Signature//wsse:Reference", namespaces=NAMESPACES).get("URI").removeprefix("#")
        for token in envelope.iterfind(".//wsse:BinarySecurityToken", namespaces=NAMESPACES):
            if (
                token.get("{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id")
                == uri
            ):
                token.text = base64.b64encode(certificate.public_bytes(Encoding.DER)).decode()

    message = parse(*send(local_party, remote_party), receiving_party, certificate, mutate)

    assert message.parse_error is not None
    assert message.parse_error.error_code == "EBMS:0103"
    assert "ECPublicKey" in message.parse_error.detail
