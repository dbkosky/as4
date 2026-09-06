from enum import Enum

from as4.models.common import BaseElement
from pydantic import Field


class LangValue(Enum):
    VALUE = ""


class Description(BaseElement):
    value: str = Field(alias="#text")
    lang: str | LangValue | None = Field(
        default=None,
        alias="@{http://www.w3.org/XML/1998/namespace}lang",
    )


class ErrorDetail(BaseElement):
    value: str = Field(alias="#text")
