from abc import ABC, abstractmethod
from typing import Self

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from lxml import etree
from as4.core.serialisation import SerialisableCertificate
from as4.errors import DuplicateElementIdException
from as4.models.ebms.user_message import PartyFrom, PartyId, PartyTo, Role
from as4.utils.xml_parser import id_attributes
from pydantic import BaseModel, ConfigDict, Field


def index_elements_by_id(
    element: etree._Element,
    message_id: str = "",
    messaging_id: str = "",
) -> dict[str, etree._Element]:
    indexed: dict[str, etree._Element] = {}
    for identifier, descendant in id_attributes(element):
        if identifier in indexed:
            raise DuplicateElementIdException(identifier)
        indexed[identifier] = descendant
    return indexed


class AS4PartyIdentity(BaseModel):
    party_id: str
    party_type: str | None = Field(default=None)

    @classmethod
    def from_party(cls, party: PartyFrom | PartyTo) -> Self:
        return cls(party_id=party.party_id.value, party_type=party.party_id.type_value)

    def to_party_from(self) -> PartyFrom:
        return PartyFrom(
            party_id=PartyId(value=self.party_id, type_value=self.party_type),
            role=Role(value="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator"),
        )

    def to_party_to(self) -> PartyTo:
        return PartyTo(
            party_id=PartyId(value=self.party_id, type_value=self.party_type),
            role=Role(value="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder"),
        )


class AS4PrivateKey(ABC):

    @abstractmethod
    def sign(
        self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: Prehashed | hashes.HashAlgorithm,
    ) -> bytes: ...

    @abstractmethod
    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes: ...


class AS4LocalPrivateKey(AS4PrivateKey):

    def __init__(self, private_key: RSAPrivateKey) -> None:
        self.private_key = private_key

    def sign(
        self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: Prehashed | hashes.HashAlgorithm,
    ) -> bytes:
        return self.private_key.sign(data, padding, algorithm)

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        return self.private_key.decrypt(ciphertext, padding)


class AS4BaseCredentials(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    certificate: SerialisableCertificate

    @property
    def rsa_public_key(self) -> RSAPublicKey:
        public_key = self.certificate.public_key()
        assert isinstance(public_key, RSAPublicKey)
        return public_key


class AS4InternalCredentials(AS4BaseCredentials):
    private_key: AS4PrivateKey


class AS4InternalParty(BaseModel):

    identity: AS4PartyIdentity
    credentials: AS4InternalCredentials = Field(exclude=True)


class AS4ExternalParty(BaseModel):

    identity: AS4PartyIdentity
    credentials: AS4BaseCredentials
