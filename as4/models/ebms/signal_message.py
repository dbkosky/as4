from as4.models.common import BaseElement, Singular, WildcardSpecification
from as4.models.ebbp.non_repudiation_information import NonRepudiationInformation
from pydantic import Field

from .description import Description, ErrorDetail
from .message_info import MessageInfo


class PullRequest(BaseElement):

    mpc: str | None = Field(default=None, alias="@mpc")

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(
            namespace="##other",
        )


class Receipt(BaseElement):

    non_repudiation_information: Singular[NonRepudiationInformation] | None = Field(
        default=None,
        alias="{http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0}NonRepudiationInformation",
    )

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(
            namespace="##other",
        )


class Error(BaseElement):
    description: Singular[Description] | None = Field(
        default=None, alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Description"
    )
    error_detail: Singular[ErrorDetail] | None = Field(
        default=None, alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}ErrorDetail"
    )
    category: str | None = Field(default=None, alias="@category")
    ref_to_message_in_error: str | None = Field(default=None, alias="@refToMessageInError")
    error_code: str = Field(alias="@errorCode")
    origin: str | None = Field(default=None, alias="@origin")
    severity: str = Field(alias="@severity")
    short_description: str | None = Field(default=None, alias="@shortDescription")


class SignalMessage(BaseElement):
    """In the core part of ebMS-3 specification, an eb:Signal Message is allowed to
    contain eb:MessageInfo and at most one Receipt Signal, at most one
    eb:PullRequest element, and/or a series of eb:Error elements.

    In part 2 of the ebMS-3 specification, new signals may be
    introduced, and for this reason, an extensibility point is added
    here to the eb:SignalMessage element to allow it to contain any
    elements.
    """

    message_info: Singular[MessageInfo] = Field(
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}MessageInfo"
    )
    pull_request: Singular[PullRequest] | None = Field(
        default=None, alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}PullRequest"
    )
    receipt: Singular[Receipt] | None = Field(
        default=None, alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Receipt"
    )
    errors: list[Error] = Field(
        default_factory=list, alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Error"
    )

    @property
    def error(self) -> Error | None:
        return self.errors[0] if self.errors else None

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(
            namespace="##other",
        )
