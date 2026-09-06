from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from lxml import etree
from as4.models.common import BaseElement, Singular, WildcardSpecification
from pydantic import Base64Bytes, Field

from .key_info import KeyInfo
from .reference import Reference, UnsupportedTransform
from .transforms import TransformAlgorithm

SIGNATURE_ALGORITHMS: dict[str, hashes.HashAlgorithm] = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": hashes.SHA256(),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": hashes.SHA384(),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": hashes.SHA512(),
}


class UnsupportedSignatureAlgorithm(Exception):
    """The signature names an algorithm outside the set this library will verify."""


class CanonicalizationMethod(BaseElement):

    algorithm: str | None = Field(alias="@Algorithm")

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(namespace="##any")

    @property
    def inclusive_namespaces(self) -> list[str]:
        prefix_list = []
        for item in self.wildcard_content:
            if not item.tag == "{http://www.w3.org/2001/10/xml-exc-c14n#}InclusiveNamespaces":
                continue
            prefix_list.extend(item.attrib.get("PrefixList", "").split())
        return prefix_list


class HMACOutputLength(BaseElement):
    text: str = Field(alias="#text")


class SignatureMethod(BaseElement):
    algorithm: str = Field(alias="@Algorithm")

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(
            namespace="##any", choices=["{http://www.w3.org/2000/09/xmldsig#}HMACOutputLength"]
        )


class SignedInfo(BaseElement):
    canonicalization_method: Singular[CanonicalizationMethod] = Field(
        alias="{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod",
    )
    signature_method: Singular[SignatureMethod] = Field(
        alias="{http://www.w3.org/2000/09/xmldsig#}SignatureMethod",
    )
    references: list[Reference] = Field(
        default_factory=list,
        alias="{http://www.w3.org/2000/09/xmldsig#}Reference",
    )
    id: str | None = Field(
        default=None,
        alias="@Id",
    )

    @property
    def signed_info_canonicalized(self) -> bytes:
        if self.etree_element is None:
            return b""

        return etree.tostring(
            self.etree_element,
            method="c14n",
            exclusive=True,
            with_comments=False,
            inclusive_ns_prefixes=self.canonicalization_method.inclusive_namespaces,
        )


class Object(BaseElement):
    id: str | None = Field(
        default=None,
        alias="@Id",
    )
    mime_type: str | None = Field(
        default=None,
        alias="@MimeType",
    )
    encoding: str | None = Field(
        default=None,
        alias="@Encoding",
    )

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(namespace="##any")


class SignatureValue(BaseElement):
    value: Base64Bytes | None = Field(default=None, alias="#text")
    id: str | None = Field(
        default=None,
        alias="@Id",
    )


class Signature(BaseElement):
    signed_info: Singular[SignedInfo] = Field(
        alias="{http://www.w3.org/2000/09/xmldsig#}SignedInfo",
    )
    signature_value: Singular[SignatureValue] = Field(
        alias="{http://www.w3.org/2000/09/xmldsig#}SignatureValue",
    )
    key_info: Singular[KeyInfo] = Field(alias="{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
    object_value: list[Object] = Field(
        default_factory=list,
        alias="{http://www.w3.org/2000/09/xmldsig#}Object",
    )
    signature_id: str | None = Field(
        default=None,
        alias="@Id",
    )

    @property
    def signature_bytes(self) -> bytes:
        if self.signature_value.value is None:
            raise ValueError("No signature bytes found for signature")
        return self.signature_value.value

    @classmethod
    def require_exclusive_canonicalization(cls, canonicalization: str | None) -> None:
        if canonicalization != TransformAlgorithm.EXCLUSIVE_C14N:
            raise UnsupportedTransform(str(canonicalization))

    @classmethod
    def require_rsa_public_key(cls, certificate: x509.Certificate, algorithm: str) -> RSAPublicKey:
        public_key = certificate.public_key()
        if not isinstance(public_key, RSAPublicKey):
            raise UnsupportedSignatureAlgorithm(f"{algorithm} with a {type(public_key).__name__}")
        return public_key

    def verify(self, certificate: x509.Certificate) -> None:
        signature_algorithm = self.signed_info.signature_method.algorithm
        self.require_exclusive_canonicalization(self.signed_info.canonicalization_method.algorithm)
        algorithm = SIGNATURE_ALGORITHMS.get(signature_algorithm)
        if algorithm is None:
            raise UnsupportedSignatureAlgorithm(signature_algorithm)
        public_key = self.require_rsa_public_key(certificate, signature_algorithm)
        public_key.verify(
            signature=self.signature_bytes,
            data=self.signed_info.signed_info_canonicalized,
            padding=padding.PKCS1v15(),
            algorithm=algorithm,
        )
