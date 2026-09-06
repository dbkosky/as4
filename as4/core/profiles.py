from abc import ABC, abstractmethod
from typing import Annotated, Any, Generic, TypeVar

from cryptography import x509
from as4.core.common import AS4ExternalParty, AS4InternalParty
from as4.core.context import AS4ParseContext
from as4.errors import BaseAS4ReceiptableError, UnknownProfileError
from as4.core.message import AS4Message
from as4.core.receipt import AS4Receipt
from as4.core.references import AS4References
from as4.core.serialisation import descendants
from pydantic import BeforeValidator, PlainSerializer

MessageType = TypeVar("MessageType", bound=AS4Message)
ReceiptType = TypeVar("ReceiptType", bound=AS4Receipt)
BuilderArgsType = TypeVar("BuilderArgsType")


class AS4Profile(ABC, Generic[MessageType, ReceiptType, BuilderArgsType]):

    @classmethod
    @abstractmethod
    def get_profile_name(cls) -> str: ...

    @classmethod
    @abstractmethod
    def message_class(cls) -> type[MessageType]: ...

    @classmethod
    @abstractmethod
    def receipt_class(cls) -> type[ReceiptType]: ...

    @classmethod
    @abstractmethod
    def build_message(
        cls,
        payload: bytes,
        *,
        local_party: AS4InternalParty,
        remote_party: AS4ExternalParty,
        builder_args: BuilderArgsType,
        references: AS4References | None = None,
    ) -> MessageType: ...

    @classmethod
    def parse_message(cls, payload: bytes, parse_context: AS4ParseContext) -> MessageType:
        try:
            soap_bytes, mime_attachments = cls.unpack_message(payload)
        except BaseAS4ReceiptableError as exception:
            message = cls.message_class()()
            message.parse_error = exception
            return message
        return cls.message_class().parse(
            parse_context=parse_context,
            soap_bytes=soap_bytes,
            mime_attachments=mime_attachments,
        )

    @classmethod
    @abstractmethod
    def unpack_message(cls, payload: bytes) -> tuple[bytes, dict[str, bytes]]: ...

    @classmethod
    @abstractmethod
    def parse_receipt(cls, payload: bytes, expected_signer: x509.Certificate) -> ReceiptType: ...

    @classmethod
    def by_name(cls, profile_name: str) -> type["AS4Profile"]:
        for profile in descendants(cls):
            if profile.get_profile_name() == profile_name:
                return profile
        raise UnknownProfileError(profile_name)

    @classmethod
    def correlate_signal(cls, payload: bytes) -> str | None:
        return cls.receipt_class().peek_original_message_id(payload)


def load_profile(value: Any) -> Any:
    return AS4Profile.by_name(value) if isinstance(value, str) else value


def dump_profile(profile: type[AS4Profile]) -> str:
    return profile.get_profile_name()


SerialisableProfile = Annotated[
    type[AS4Profile],
    BeforeValidator(load_profile),
    PlainSerializer(dump_profile, return_type=str, when_used="json"),
]
