from enum import StrEnum

from as4.models.common import BaseElement, Singular, WildcardSpecification
from as4.models.dsig.reference import DigestMethod
from pydantic import Field

from ..dsig.key_info import KeyInfo
from ..dsig.transforms import Transform
from .reference import ReferenceList


class EncryptionAlgorithm(StrEnum):
    RSA_OAEP = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
    AES128_GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"


class MGF(BaseElement):
    algorithm: str = Field(alias="@Algorithm")


class KeySize(BaseElement):
    value: int = Field(alias="#text")


class OAEPparams(BaseElement):
    value: bytes = Field(alias="#text")


class EncryptionMethod(BaseElement):
    algorithm: str = Field(alias="@Algorithm")
    digest_method: Singular[DigestMethod] | None = Field(
        alias="{http://www.w3.org/2000/09/xmldsig#}DigestMethod", default=None
    )
    mgf: Singular[MGF] | None = Field(alias="{http://www.w3.org/2009/xmlenc11#}MGF", default=None)

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(
            namespace="##any",
            choices=[
                "{http://www.w3.org/2000/09/xmldsig#}KeySize",
                "{http://www.w3.org/2000/09/xmldsig#}OAEPparams",
            ],
        )


class Transforms(BaseElement):
    transforms: list[Transform] = Field(
        default_factory=list,
        alias="{http://www.w3.org/2000/09/xmldsig#}Transform",
        min_length=1,
    )


class CipherReference(BaseElement):
    transforms: Singular[Transforms] = Field(alias="{http://www.w3.org/2001/04/xmlenc#}Transforms")
    uri: str | None = Field(default=None, alias="@URI")


class CipherValue(BaseElement):
    value: str | None = Field(default=None, alias="#text")


class CipherData(BaseElement):
    cipher_value: Singular[CipherValue] | None = Field(
        alias="{http://www.w3.org/2001/04/xmlenc#}CipherValue",
        default=None,
    )
    cipher_reference: Singular[CipherReference] | None = Field(
        alias="{http://www.w3.org/2001/04/xmlenc#}CipherReference",
        default=None,
    )


class EncryptionProperty(BaseElement):

    target: str | None = Field(
        default=None,
        alias="@Target",
    )
    id: str | None = Field(
        default=None,
        alias="@Id",
    )

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(
            namespace="##any",
        )


class EncryptionProperties(BaseElement):
    encryption_property: list[EncryptionProperty] = Field(
        default_factory=list,
        alias="{http://www.w3.org/2001/04/xmlenc#}EncryptionProperty",
        min_length=1,
    )
    id: str | None = Field(default=None, alias="@Id")


class EncryptedType(BaseElement):
    encryption_method: Singular[EncryptionMethod] = Field(
        alias="{http://www.w3.org/2001/04/xmlenc#}EncryptionMethod",
    )
    key_info: Singular[KeyInfo] = Field(alias="{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
    cipher_data: Singular[CipherData] = Field(alias="{http://www.w3.org/2001/04/xmlenc#}CipherData")
    encryption_properties: list[EncryptionProperties] = Field(
        default_factory=list,
        alias="{http://www.w3.org/2001/04/xmlenc#}EncryptionProperties",
    )
    encrypted_type_id: str | None = Field(default=None, alias="@Id")
    type_value: str | None = Field(default=None, alias="@Type")
    mime_type: str | None = Field(default=None, alias="@MimeType")
    encoding: str | None = Field(default=None, alias="@Encoding")


class CarriedKeyName(BaseElement):
    text: str | None = Field(default=None, alias="#text")


class EncryptedKey(EncryptedType):
    reference_list: Singular[ReferenceList] = Field(alias="{http://www.w3.org/2001/04/xmlenc#}ReferenceList")
    carried_key_name: list[CarriedKeyName] = Field(
        default_factory=list, alias="{http://www.w3.org/2001/04/xmlenc#}CarriedKeyName"
    )
    recipient: str | None = Field(default=None, alias="@Recipient")
