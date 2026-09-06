from as4.models.common import BaseElement, Singular
from pydantic import Field

from ..dsig.signature import Signature
from ..xenc.encrypted_type import EncryptedKey, EncryptedType
from .binary_security_token import BinarySecurityToken


class Security(BaseElement):
    binary_security_tokens: list[BinarySecurityToken] = Field(
        alias="{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken"
    )
    encrypted_key: Singular[EncryptedKey] | None = Field(
        alias="{http://www.w3.org/2001/04/xmlenc#}EncryptedKey", default=None
    )
    encrypted_data: list[EncryptedType] | None = Field(
        alias="{http://www.w3.org/2001/04/xmlenc#}EncryptedData", default=None
    )
    signature: Singular[Signature] | None = Field(alias="{http://www.w3.org/2000/09/xmldsig#}Signature", default=None)
    must_understand: bool = Field(alias="@{http://www.w3.org/2003/05/soap-envelope}mustUnderstand", default=True)

    def get_encrypted_data(self, encrypted_data_id: str) -> EncryptedType | None:
        if self.encrypted_data is None:
            return None

        for encrypted_data in self.encrypted_data:
            if encrypted_data.encrypted_type_id == encrypted_data_id:
                return encrypted_data

        return None
