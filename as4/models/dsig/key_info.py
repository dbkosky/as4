from __future__ import annotations

from as4.models.common import BaseElement, Singular, WildcardSpecification
from as4.models.wsse.security_token_reference import SecurityTokenReference
from pydantic import Base64Bytes, Field

from .transforms import Transforms


WSSE_SECURITY_TOKEN_ALIAS = (
    "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}SecurityTokenReference"
)


class CryptoBinary(BaseElement):
    text: Base64Bytes = Field(alias="#text")


class DSAKeyValue(BaseElement):
    p: Singular[CryptoBinary] | None = Field(alias="{http://www.w3.org/2000/09/xmldsig#}P")
    q: Singular[CryptoBinary] | None = Field(default=None, alias="{http://www.w3.org/2000/09/xmldsig#}Q")
    g: Singular[CryptoBinary] | None = Field(default=None, alias="{http://www.w3.org/2000/09/xmldsig#}G")
    y: Singular[CryptoBinary] | None = Field(default=None, alias="{http://www.w3.org/2000/09/xmldsig#}Y")
    j: Singular[CryptoBinary] | None = Field(default=None, alias="{http://www.w3.org/2000/09/xmldsig#}J")
    seed: Singular[CryptoBinary] | None = Field(default=None, alias="{http://www.w3.org/2000/09/xmldsig#}Seed")
    pgen_counter: Singular[CryptoBinary] | None = Field(
        default=None, alias="{http://www.w3.org/2000/09/xmldsig#}PgenCounter"
    )


class RSAKeyValue(BaseElement):

    modulus: Singular[CryptoBinary] = Field(alias="{http://www.w3.org/2000/09/xmldsig#}Modulus")
    exponent: Singular[CryptoBinary] = Field(alias="{http://www.w3.org/2000/09/xmldsig#}Exponent")


class KeyValue(BaseElement):

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(
            namespace="##any",
            choices=[
                "{http://www.w3.org/2000/09/xmldsig#}DSAKeyValue",
                "{http://www.w3.org/2000/09/xmldsig#}RSAKeyValue",
            ],
        )


class KeyName(BaseElement):
    text: str = Field(alias="#text")


class RetrievalMethod(BaseElement):
    transforms: list[Transforms] = Field(default_factory=list, alias="{http://www.w3.org/2000/09/xmldsig#}Transforms")
    uri: str | None = Field(default=None, alias="@URI")
    type_value: str | None = Field(default=None, alias="@Type")


class X509IssuerName(BaseElement):
    text: str = Field(alias="#text")


class X509SerialNumber(BaseElement):
    text: int = Field(alias="#text")


class X509IssuerSerial(BaseElement):
    x509_issuer_name: Singular[X509IssuerName] = Field(alias="{http://www.w3.org/2000/09/xmldsig#}X509IssuerName")
    x509_serial_number: Singular[X509SerialNumber] = Field(
        alias="{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber"
    )


class X509SKI(BaseElement):
    text: Base64Bytes = Field(alias="#text")


class X509SubjectName(BaseElement):
    text: str = Field(alias="#text")


class X509Certificate(BaseElement):
    text: Base64Bytes = Field(alias="#text")


class X509CRL(BaseElement):
    text: Base64Bytes = Field(alias="#text")


class X509Data(BaseElement):
    x509_issuer_serial: list[X509IssuerSerial] = Field(
        default_factory=list,
        alias="{http://www.w3.org/2000/09/xmldsig#}X509IssuerSerial",
        min_length=1,
    )
    x509_ski: list[X509SKI] = Field(
        default_factory=list,
        alias="{http://www.w3.org/2000/09/xmldsig#}X509SKI",
        min_length=1,
    )
    x509_subject_name: list[X509SubjectName] = Field(
        default_factory=list,
        alias="{http://www.w3.org/2000/09/xmldsig#}X509SubjectName",
        min_length=1,
    )
    x509_certificate: list[X509Certificate] = Field(
        default_factory=list,
        alias="{http://www.w3.org/2000/09/xmldsig#}X509Certificate",
        min_length=1,
    )
    x509_crl: list[X509CRL] = Field(
        default_factory=list,
        alias="{http://www.w3.org/2000/09/xmldsig#}X509CRL",
        min_length=1,
    )


class PGPData(BaseElement):
    pgpkey_id: Singular[CryptoBinary] = Field(alias="{http://www.w3.org/2000/09/xmldsig#}PGPKeyID")
    pgpkey_packet: list[CryptoBinary] = Field(
        default_factory=list, alias="{http://www.w3.org/2000/09/xmldsig#}PGPKeyPacket"
    )  # TODO max occurs validator = 2


class SPKIData(BaseElement):
    spkisexp: list[CryptoBinary] = Field(
        default_factory=list, alias="{http://www.w3.org/2000/09/xmldsig#}SPKISexp"
    )  # TODO min occurs validator = 1


class MgmtData(BaseElement):
    text: str = Field(default="", alias="#text")


class KeyInfo(BaseElement):
    key_info_id: str | None = Field(default=None, alias="@Id")

    key_name: list[KeyName] = Field(default_factory=list, alias="{http://www.w3.org/2000/09/xmldsig#}KeyName")
    key_value: list[KeyValue] = Field(default_factory=list, alias="{http://www.w3.org/2000/09/xmldsig#}KeyValue")
    retrieval_method: list[RetrievalMethod] = Field(
        default_factory=list, alias="{http://www.w3.org/2000/09/xmldsig#}RetrievalMethod"
    )
    x509_data: list[X509Data] = Field(default_factory=list, alias="{http://www.w3.org/2000/09/xmldsig#}X509Data")
    pgp_data: list[PGPData] = Field(default_factory=list, alias="{http://www.w3.org/2000/09/xmldsig#}PGPData")
    spki_data: list[SPKIData] = Field(default_factory=list, alias="{http://www.w3.org/2000/09/xmldsig#}SPKIData")
    mgmt_data: list[MgmtData] = Field(default_factory=list, alias="{http://www.w3.org/2000/09/xmldsig#}MgmtData")
    security_token_reference: list[SecurityTokenReference] = Field(
        default_factory=list,
        alias=WSSE_SECURITY_TOKEN_ALIAS,
    )
