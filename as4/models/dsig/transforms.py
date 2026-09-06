from enum import StrEnum

from as4.models.common import BaseElement, WildcardSpecification
from pydantic import Field


class TransformAlgorithm(StrEnum):
    EXCLUSIVE_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
    ATTACHMENT_CONTENT_SIGNATURE = (
        "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform"
    )


class Transform(BaseElement):
    algorithm: str | None = Field(
        default=None,
        alias="@Algorithm",
    )

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(namespace="##any")

    @property
    def inclusive_namespaces(self) -> list[str]:
        prefix_list = []
        for item in self.wildcard_content:
            if not item.tag == "{http://www.w3.org/2001/10/xml-exc-c14n#}InclusiveNamespaces":
                continue
            prefix_list.extend(item.attrib.get("PrefixList", "").split())
        return prefix_list


class Transforms(BaseElement):
    transforms: list[Transform] = Field(
        default_factory=list,
        alias="{http://www.w3.org/2000/09/xmldsig#}Transform",
    )  # TODO min occurs validator = 1
