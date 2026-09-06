import json
from abc import ABC, abstractmethod
from contextlib import suppress
from datetime import UTC, datetime
from enum import StrEnum
from typing import Generic, Self, TypeVar

from cryptography import x509
from as4.core.common import AS4ExternalParty, AS4InternalParty
from as4.core.context import AS4ParseContext, ParticipantAcceptor, SecurityPolicy
from as4.errors import (
    MismatchedLocalPartyError,
    ReceiptVerificationError,
    RemotePartyNotVerifiedError,
    UserMessageNotFoundException,
)
from as4.core.message import AS4Message
from as4.core.profiles import SerialisableProfile
from as4.core.receipt import AS4Receipt
from as4.core.references import AS4References
from as4.models.dsig.reference import ComparableReferenceFields
from as4.models.ebms.signal_message import Error
from as4.utils.mime_handler import MIMEHandler
from pydantic import BaseModel, ConfigDict, Field, model_validator

MessageType = TypeVar("MessageType", bound=AS4Message)
ReceiptType = TypeVar("ReceiptType", bound=AS4Receipt)
BuilderArgsType = TypeVar("BuilderArgsType")


class ExchangeState(StrEnum):
    CREATED = "created"
    BUILT = "built"
    SENT = "sent"
    RECEIVED = "received"
    ACKNOWLEDGED = "acknowledged"
    REJECTED = "rejected"
    FAILED = "failed"


class AS4Exchange(BaseModel, ABC, Generic[MessageType, ReceiptType, BuilderArgsType]):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    profile: SerialisableProfile
    local_party: AS4InternalParty

    message_id: str = ""
    messaging_id: str = ""
    identifiers: AS4References = Field(default_factory=AS4References)

    state: ExchangeState = ExchangeState.CREATED
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    signed_references: list[ComparableReferenceFields] = Field(default_factory=list)
    required_references: list[ComparableReferenceFields] | None = None

    message: MessageType | None = None
    receipt: ReceiptType | None = None

    @property
    def errors(self) -> list[Error]:
        return self.receipt.errors if self.receipt else []

    @property
    def error(self) -> Error | None:
        return self.errors[0] if self.errors else None

    @property
    def conversation_id(self) -> str | None:
        return self.message.conversation_id if self.message is not None else None

    @property
    @abstractmethod
    def successful(self) -> bool: ...

    @classmethod
    def restore(cls, serialised_exchange: str, local_party: AS4InternalParty) -> Self:
        stored = json.loads(serialised_exchange)
        stored_party_id = stored["local_party"]["identity"]["party_id"]
        if stored_party_id != local_party.identity.party_id:
            raise MismatchedLocalPartyError(stored_party_id, local_party.identity.party_id)
        return cls.model_validate({**stored, "local_party": local_party})


class AS4SendingExchange(AS4Exchange[MessageType, ReceiptType, BuilderArgsType]):
    """The side that sends the user message: it builds one, sends it, and takes in the signal answering it."""

    remote_party: AS4ExternalParty

    @model_validator(mode="after")
    def default_message_ids_from_identifiers(self) -> Self:
        self.message_id = self.message_id or self.identifiers.message_id
        self.messaging_id = self.messaging_id or self.identifiers.messaging_id
        return self

    @property
    def conversation_id(self) -> str | None:
        if self.message is not None:
            return super().conversation_id
        return self.identifiers.conversation_id

    @property
    def successful(self) -> bool:
        return self.state is ExchangeState.ACKNOWLEDGED

    @property
    def expected_signer(self) -> x509.Certificate:
        return self.remote_party.credentials.certificate

    def build(self, payload: bytes, builder_args: BuilderArgsType) -> tuple[dict[str, str], bytes]:
        message = self.profile.build_message(
            payload,
            local_party=self.local_party,
            remote_party=self.remote_party,
            builder_args=builder_args,
            references=self.identifiers,
        )
        body, boundary = message.get_request_data()
        headers = message.get_http_headers(boundary)

        self.message = message
        self.message_id = message.message_id
        self.messaging_id = message.messaging_id
        self.signed_references = message.signed_references
        self.state = ExchangeState.BUILT
        return headers, body

    def mark_sent(self) -> Self:
        self.state = ExchangeState.SENT
        return self

    def receive_signal(self, signal_data: bytes) -> Self:
        """The receipt and the state are recorded before an unproven signal raises, so both stay inspectable."""
        receipt = self.profile.parse_receipt(signal_data, self.expected_signer)
        if receipt.original_message_id != self.message_id:
            raise ReceiptVerificationError(
                f"Signal refers to {receipt.original_message_id!r}, not to this exchange's {self.message_id!r}"
            )
        state = ExchangeState.ACKNOWLEDGED
        unproven = None
        if receipt.error is not None:
            state = ExchangeState.REJECTED
        else:
            try:
                receipt.verify_non_repudiation(self.signed_references, self.required_references)
            except ReceiptVerificationError as exception:
                state, unproven = ExchangeState.FAILED, exception

        self.receipt = receipt
        self.state = state
        if unproven is not None:
            raise unproven
        return self


class AS4ReceivingExchange(AS4Exchange[MessageType, ReceiptType, BuilderArgsType]):
    """The side that receives the user message: it parses one and answers it with a signal."""

    remote_party: AS4ExternalParty | None = None

    @property
    def successful(self) -> bool:
        return self.state is ExchangeState.RECEIVED

    def receive(
        self,
        request_headers: dict,
        request_body: bytes,
        accept_participant: ParticipantAcceptor | None = None,
        security_policy: SecurityPolicy | None = None,
    ) -> Self:
        parse_context = AS4ParseContext(
            local_party=self.local_party,
            accept_participant=accept_participant,
            security_policy=security_policy or SecurityPolicy(),
        )
        payload = MIMEHandler.payload_from_request(request_headers, request_body)
        return self.receive_message(self.profile.parse_message(payload, parse_context))

    def receive_message(self, message: MessageType) -> Self:
        remote_party = self.remote_party
        with suppress(RemotePartyNotVerifiedError, UserMessageNotFoundException):
            remote_party = message.get_remote_party()
        receipt = self.profile.receipt_class().for_message(
            message=message,
            local_party=self.local_party,
            references=self.identifiers,
        )

        self.message = message
        self.message_id = message.message_id
        self.messaging_id = message.messaging_id
        self.signed_references = message.signed_references
        self.remote_party = remote_party
        self.receipt = receipt
        self.state = ExchangeState.REJECTED if message.parse_error else ExchangeState.RECEIVED
        return self

    def build_signal(self) -> tuple[dict[str, str], bytes]:
        if self.receipt is None:
            raise ValueError("Exchange has no signal to send; nothing has been received yet")
        return self.receipt.get_request_data()
