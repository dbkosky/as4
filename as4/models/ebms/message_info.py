from datetime import datetime

from as4.models.common import BaseElement, Singular
from pydantic import Field


class Timestamp(BaseElement):
    value: datetime = Field(alias="#text")


class MessageId(BaseElement):
    value: str = Field(alias="#text")


class RefToMessageId(BaseElement):
    value: str = Field(alias="#text")


class MessageInfo(BaseElement):
    timestamp: Singular[Timestamp] = Field(
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Timestamp"
    )
    message_id: Singular[MessageId] = Field(
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}MessageId"
    )
    ref_to_message_id: Singular[RefToMessageId] | None = Field(
        default=None,
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}RefToMessageId",
    )
