from as4.models.common import BaseElement, Singular, WildcardSpecification
from pydantic import Field

from .header import Header


class Body(BaseElement):

    body_id: str | None = Field(
        default=None, alias="@{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id"
    )

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(namespace="##any")


class Envelope(BaseElement):
    header: Singular[Header] = Field(alias="{http://www.w3.org/2003/05/soap-envelope}Header")
    body: Singular[Body] = Field(alias="{http://www.w3.org/2003/05/soap-envelope}Body")
