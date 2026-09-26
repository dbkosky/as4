"""The P-Mode: one agreement between two parties about how they exchange messages.

A P-Mode is data only. A profile makes and checks P-Modes; building and parsing read them.
Trust anchors are not here: which certificates a deployment trusts comes from the deployment,
and a leg only pins the certificates particular to one partner.
"""

from datetime import timedelta
from enum import StrEnum
from typing import Self

from as4 import const
from as4.core.common import AS4PartyIdentity
from as4.core.serialisation import SerialisableCertificate
from pydantic import BaseModel, ConfigDict, Field, model_validator


class MEP(StrEnum):
    ONE_WAY = const.MEP_ONE_WAY
    TWO_WAY = const.MEP_TWO_WAY


class MEPBinding(StrEnum):
    PUSH = const.MEP_BINDING_PUSH
    PULL = const.MEP_BINDING_PULL


class ReceiptReplyPattern(StrEnum):
    RESPONSE = "response"
    CALLBACK = "callback"


class PModeParty(BaseModel):
    model_config = ConfigDict(frozen=True)

    party_id: str
    party_type: str | None = None
    role: str

    @property
    def identity(self) -> AS4PartyIdentity:
        return AS4PartyIdentity(party_id=self.party_id, party_type=self.party_type)


class PModeLegProtocol(BaseModel):
    model_config = ConfigDict(frozen=True)

    # The receiving MSH's endpoint. Unset when this side is the receiver.
    address: str | None = None
    soap_version: str = "1.2"


class PModeLegBusinessInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    # An unset service or action matches any value, for profiles where these vary per message.
    service: str | None = None
    service_type: str | None = None
    action: str | None = None
    mpc: str = const.DEFAULT_MPC


class PModeLegErrorHandling(BaseModel):
    model_config = ConfigDict(frozen=True)

    report_as_response: bool = True
    report_sender_errors_to: str | None = None
    report_receiver_errors_to: str | None = None
    process_error_notify_consumer: bool = False
    process_error_notify_producer: bool = False
    delivery_failures_notify_producer: bool = False


class PModeLegSecurity(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    sign_required: bool = True
    signature_algorithm: str
    signature_digest_algorithm: str
    # A certificate pinned for this partner. Unset means the deployment's trust decides.
    signature_certificate: SerialisableCertificate | None = None

    encrypt_required: bool = True
    encryption_algorithm: str
    encryption_minimum_strength: int | None = None
    encryption_certificate: SerialisableCertificate | None = None

    required_coverage: frozenset[str] = frozenset({"messaging", "body", "payloads"})

    send_receipt: bool = True
    receipt_non_repudiation: bool = True
    receipt_reply_pattern: ReceiptReplyPattern = ReceiptReplyPattern.RESPONSE


class PModeLeg(BaseModel):
    model_config = ConfigDict(frozen=True)

    protocol: PModeLegProtocol = Field(default_factory=PModeLegProtocol)
    business_info: PModeLegBusinessInfo = Field(default_factory=PModeLegBusinessInfo)
    error_handling: PModeLegErrorHandling = Field(default_factory=PModeLegErrorHandling)
    security: PModeLegSecurity


class PModeReceptionAwareness(BaseModel):
    """as4 carries these but does not act on them: retrying is the caller's job."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    retry: bool = True
    max_retries: int = Field(default=1, ge=0)
    retry_interval: timedelta = timedelta(seconds=10)
    duplicate_detection: bool = True


class PMode(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    agreement: str | None = None
    mep: MEP = MEP.ONE_WAY
    binding: MEPBinding = MEPBinding.PUSH
    initiator: PModeParty
    responder: PModeParty
    leg1: PModeLeg
    leg2: PModeLeg | None = None
    reception_awareness: PModeReceptionAwareness = Field(default_factory=PModeReceptionAwareness)

    @model_validator(mode="after")
    def legs_match_the_mep(self) -> Self:
        if self.mep is MEP.ONE_WAY and self.leg2 is not None:
            raise ValueError("A one-way P-Mode has a single leg")
        if self.mep is MEP.TWO_WAY and self.leg2 is None:
            raise ValueError("A two-way P-Mode needs a second leg")
        return self
