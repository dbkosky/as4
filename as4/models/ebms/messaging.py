from typing import TypeVar

from as4.errors import BundledMessagesNotSupportedException
from as4.models.common import BaseElement, WildcardSpecification
from pydantic import Field

from .signal_message import SignalMessage
from .user_message import UserMessage

MessageT = TypeVar("MessageT", SignalMessage, UserMessage)


class Messaging(BaseElement):
    """The eb:Messaging element is the top element of ebMS-3 headers, and it is
    placed within the SOAP Header element (either SOAP 1.1 or SOAP 1.2).

    The eb:Messaging element may contain several instances of
    eb:SignalMessage and eb:UserMessage elements. However in the core
    part of the ebMS-3 specification, only one instance of either
    eb:UserMessage or eb:SignalMessage must be present. The second part
    of ebMS-3 specification may need to include multiple instances of
    either eb:SignalMessage, eb:UserMessage or both. Therefore, this
    schema is allowing multiple instances of eb:SignalMessage and
    eb:UserMessage elements for part 2 of the ebMS-3 specification. Note
    that the eb:Messaging element cannot be empty (at least one of
    eb:SignalMessage or eb:UserMessage element must present).

    :ivar signal_messages:
    :ivar user_messages:
    :ivar other_element:
    :ivar id:
    :ivar w3_org_2003_05_soap_envelope_must_understand: if SOAP 1.2 is
        being used, this attribute is required
    :ivar other_attributes:
    """

    signal_messages: list[SignalMessage] = Field(
        default_factory=list,
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}SignalMessage",
    )
    user_messages: list[UserMessage] = Field(
        default_factory=list,
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}UserMessage",
    )
    messaging_id: str | None = Field(
        default=None, alias="@{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id"
    )
    w3_org_2003_05_soap_envelope_must_understand: bool | None = Field(
        default=None, alias="@{http://www.w3.org/2003/05/soap-envelope}mustUnderstand"
    )

    @classmethod
    def only_one(cls, messages: list[MessageT], element_name: str) -> MessageT | None:
        match messages:
            case []:
                return None
            case [only]:
                return only
        raise BundledMessagesNotSupportedException(
            detail=f"found {len(messages)} {element_name} elements, bundling is not supported"
        )

    @property
    def signal_message(self) -> SignalMessage | None:
        return self.only_one(self.signal_messages, "eb:SignalMessage")

    @property
    def user_message(self) -> UserMessage | None:
        return self.only_one(self.user_messages, "eb:UserMessage")

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(
            namespace="##other",
        )
