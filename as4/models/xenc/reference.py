from as4.models.common import BaseElement, WildcardSpecification
from pydantic import Field


class Reference(BaseElement):

    uri: str | None = Field(default=None, alias="@URI")

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(
            namespace="##other",
        )


class ReferenceList(BaseElement):

    data_reference: list[Reference] = Field(
        default_factory=list, alias="{http://www.w3.org/2001/04/xmlenc#}DataReference"
    )
    key_reference: list[Reference] = Field(
        default_factory=list, alias="{http://www.w3.org/2001/04/xmlenc#}KeyReference"
    )
