import base64

from cryptography import x509
from as4.models.common import BaseElement
from pydantic import Field

X509_TOKEN_PROFILE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0"


class UnsupportedSecurityTokenType(Exception):
    """The token is well formed but names a value type this library cannot verify against."""


class BinarySecurityToken(BaseElement):
    encoding_type: str = Field(alias="@EncodingType")
    value_type: str = Field(alias="@ValueType")
    bst_id: str = Field(
        alias="@{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id"
    )
    value: str = Field(alias="#text")

    @property
    def x509_certificate(self) -> x509.Certificate:
        if self.value_type != f"{X509_TOKEN_PROFILE}#X509v3":
            raise UnsupportedSecurityTokenType(self.value_type)
        x509_certificate_bytes = base64.b64decode(self.value)
        x509_certificate = x509.load_der_x509_certificate(x509_certificate_bytes)
        return x509_certificate
