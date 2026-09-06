from as4.models.common import BaseElement, Singular, WildcardSpecification
from pydantic import Field


class Reference(BaseElement):
    uri: str | None = Field(default=None, alias="@URI")
    value_type: str | None = Field(default=None, alias="@ValueType")

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(
            namespace="##any",
        )


class SecurityTokenReference(BaseElement):
    security_token_reference_id: str | None = Field(
        default=None, alias="@{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id"
    )
    usage: str = Field(
        default="",
        alias="@{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Usage",
    )
    reference: Singular[Reference] = Field(
        alias="{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Reference"
    )
    token_type: str | None = Field(
        alias="@{http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd}TokenType", default=None
    )

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(
            namespace="##any",
        )
