import base64

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from lxml import etree
from as4.models.dsig.key_info import KeyInfo
from tests.assets.test_credentials import test_sender

DSIG = "http://www.w3.org/2000/09/xmldsig#"


def test_security_key_info(expected_security_key_info_object, example_security_key_info_object):
    assert example_security_key_info_object.model_dump() == expected_security_key_info_object.model_dump()


def test_signature_key_info(expected_signature_key_info_object, example_signature_key_info_object):
    assert example_signature_key_info_object.model_dump() == expected_signature_key_info_object.model_dump()


def test_an_inline_x509_certificate_is_read_as_a_certificate():
    """The wsse:BinarySecurityToken form is Peppol's, but an inline certificate is common elsewhere."""
    der = test_sender.certificate.public_bytes(Encoding.DER)
    element = etree.fromstring(
        f'<KeyInfo xmlns="{DSIG}"><X509Data><X509Certificate>'
        f"{base64.b64encode(der).decode()}"
        f"</X509Certificate></X509Data></KeyInfo>".encode()
    )

    (x509_data,) = KeyInfo.model_validate_etree(element).x509_data

    (certificate,) = x509_data.x509_certificate
    assert x509.load_der_x509_certificate(certificate.text) == test_sender.certificate
