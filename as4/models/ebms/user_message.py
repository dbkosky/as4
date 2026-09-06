import gzip
import io
import zlib

from as4 import const
from as4.errors import DecompressedPayloadTooLargeException, DecompressionFailedException
from as4.models.common import BaseElement, Singular
from pydantic import Field

from .description import Description
from .message_info import MessageInfo


class AgreementRef(BaseElement):
    value: str = Field(alias="#text")
    type_value: str | None = Field(default=None, alias="@type")
    pmode: str | None = Field(default=None, alias="@pmode")


class PartyId(BaseElement):
    value: str = Field(default="", alias="#text")
    type_value: str | None = Field(default=None, alias="@type")


class Role(BaseElement):
    value: str = Field(alias="#text")


class PartyFrom(BaseElement):
    party_id: Singular[PartyId] = Field(
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}PartyId",
    )
    role: Singular[Role] = Field(alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Role")


class PartyTo(BaseElement):
    party_id: Singular[PartyId] = Field(
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}PartyId",
    )
    role: Singular[Role] = Field(alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Role")


class PartyInfo(BaseElement):
    party_from: Singular[PartyFrom] = Field(
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}From"
    )
    party_to: Singular[PartyTo] = Field(alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}To")


class Property(BaseElement):
    property_type: str | None = Field(alias="@type", default=None)
    value: str = Field(alias="#text")
    name: str = Field(alias="@name")


class Service(BaseElement):
    value: str = Field(alias="#text")
    type_value: str | None = Field(default=None, alias="@type")


class Action(BaseElement):
    value: str = Field(alias="#text")


class ConversationId(BaseElement):
    value: str = Field(alias="#text")


class CollaborationInfo(BaseElement):
    agreement_ref: Singular[AgreementRef] | None = Field(
        default=None,
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}AgreementRef",
    )
    service: Singular[Service] = Field(alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Service")
    action: Singular[Action] = Field(alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Action")
    conversation_id: Singular[ConversationId] = Field(
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}ConversationId",
    )


class MessageProperties(BaseElement):
    properties: list[Property] = Field(
        default_factory=list,
        min_length=1,
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Property",
    )

    def get_property(self, name: str) -> Property | None:
        return next((prop for prop in self.properties if prop.name == name), None)

    @property
    def original_sender(self) -> Property | None:
        return self.get_property(const.ORIGINAL_SENDER)

    @property
    def final_recipient(self) -> Property | None:
        return self.get_property(const.FINAL_RECIPIENT)


class Schema(BaseElement):
    location: str = Field(alias="@location")
    version: str | None = Field(default=None, alias="@version", min_length=1)
    namespace: str | None = Field(default=None, alias="@namespace", min_length=1)


class PartProperties(BaseElement):
    properties: list[Property] = Field(
        default_factory=list,
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Property",
        min_length=1,
    )

    @property
    def compression_type(self) -> str | None:
        for part_property in self.properties:
            if part_property.name == "CompressionType":
                return part_property.value
        return None

    def decompress(
        self,
        decrypted_part_content: bytes,
        maximum_size: int,
    ) -> bytes:
        if self.compression_type != "application/gzip":
            return decrypted_part_content
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(decrypted_part_content)) as stream:
                decompressed = stream.read(maximum_size + 1)
        except (OSError, EOFError, zlib.error) as exception:
            raise DecompressionFailedException() from exception
        if len(decompressed) > maximum_size:
            raise DecompressedPayloadTooLargeException()
        return decompressed


class PartInfo(BaseElement):
    part_schema: list[Schema] = Field(
        default_factory=list, alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Schema"
    )
    description: list[Description] = Field(
        default_factory=list, alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Description"
    )
    part_properties: Singular[PartProperties] = Field(
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}PartProperties"
    )
    href: str | None = Field(default=None, alias="@href")


class PayloadInfo(BaseElement):
    part_info: list[PartInfo] = Field(
        default_factory=list,
        min_length=1,
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}PartInfo",
    )

    def get_part_info(self, part_cid: str) -> PartInfo | None:
        for part_info in self.part_info:
            if part_info.href == part_cid:
                return part_info
        return None


class UserMessage(BaseElement):
    message_info: Singular[MessageInfo] = Field(
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}MessageInfo"
    )
    party_info: Singular[PartyInfo] = Field(
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}PartyInfo"
    )
    collaboration_info: Singular[CollaborationInfo] = Field(
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}CollaborationInfo"
    )
    message_properties: Singular[MessageProperties] | None = Field(
        default=None, alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}MessageProperties"
    )
    payload_info: Singular[PayloadInfo] | None = Field(
        default=None, alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}PayloadInfo"
    )
    mpc: str | None = Field(default=None, alias="@mpc")
