import base64
import functools
import types
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Callable, Self, TypeVar, Union, cast, get_args, get_origin

from lxml import etree
from as4.errors import RepeatedElement
from pydantic import BaseModel, BeforeValidator, ConfigDict, EncodedBytes, Field
from pydantic.types import Base64Encoder

NAMESPACES = {
    "S12": "http://www.w3.org/2003/05/soap-envelope",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "eb3": "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/",
    "enc": "http://www.w3.org/2001/04/xmlenc#",
    "wsr": "http://docs.oasis-open.org/wsrm/2004/06/ws-reliability-1.1.xsd",
    "wsrx": "http://docs.oasis-open.org/ws-rx/wsrm/200702",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
    "ebbpsig": "http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0",
}
for prefix, namespace in NAMESPACES.items():
    etree.register_namespace(prefix, namespace)


T = TypeVar("T", bound=BaseModel)


def exactly_one(elems: list[T] | T) -> T:
    if isinstance(elems, list):
        if len(elems) > 1:
            raise RepeatedElement(f"expected exactly one element, got {len(elems)}")
        if not elems:
            raise ValueError("expected exactly one element, got 0")
        return elems[0]
    return elems


Singular = Annotated[T, BeforeValidator(exactly_one)]
Sorted = Annotated[list[str], BeforeValidator(sorted)]


@dataclass(frozen=True)
class WildcardSpecification:

    max_occurs: int = 0
    min_occurs: int = 0
    namespace: str = "##any"
    choices: list[str] | None = None

    @classmethod
    def split_clark_tag(cls, tag: str):
        *namespace, name = tag.split("}")
        if namespace:
            return namespace[0][1:], name
        return [name]

    def filter_by_namespace(self, elements: list[etree._Element]) -> list[etree._Element]:
        match self.namespace:
            case "##any":
                return elements
        return elements

    def filter_by_choices(self, elements: list[etree._Element]) -> list[etree._Element]:
        if self.choices is None:
            return elements
        return [element for element in elements if element.tag in self.choices]

    def get_content_from_element(
        self,
        element: etree._Element | None,
        existing_tags: set[str],
    ) -> list[etree._Element]:
        if element is None:
            return []

        elements = [child_element for child_element in list(element) if child_element.tag not in existing_tags]
        elements = self.filter_by_namespace(elements)
        elements = self.filter_by_choices(elements)
        return elements


class BaseElement(BaseModel):

    model_config = ConfigDict(
        validate_by_name=True,
        validate_by_alias=True,
        arbitrary_types_allowed=True,
    )
    etree_element: etree._Element | None = Field(default=None, alias="*etree_element", exclude=True)

    @property
    def wildcard_content(self) -> list[etree._Element]:
        if wildcard_spec := self.wildcard_specification():
            existing_tags = {field_info.alias for field_info in type(self).model_fields.values() if field_info.alias}
            return wildcard_spec.get_content_from_element(
                element=self.etree_element,
                existing_tags=existing_tags,
            )
        return []

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification | None:
        return None

    @classmethod
    def element_to_dict(cls, element: etree._Element):
        element_dict: dict[str, object] = {
            "*etree_element": element,
        }

        child_element_dict: dict[str, list[dict]] = {}
        for child_element in element:
            child_as_dict = cls.element_to_dict(child_element)
            child_element_dict.setdefault(child_element.tag, []).append(child_as_dict)

        for child_element_tag, child_element_list in child_element_dict.items():
            element_dict[child_element_tag] = child_element_list

        for k, v in element.attrib.items():
            element_dict["@" + cast(str, k)] = v

        if element.text and (text := element.text.strip()):
            element_dict["#text"] = text

        return element_dict

    @classmethod
    def model_validate_etree(cls, etree_element: etree._Element) -> Self:
        return cls.model_validate(cls.element_to_dict(etree_element))

    @classmethod
    def split_clark_tag(cls, tag: str):
        *namespace, name = tag.split("}")
        if namespace:
            return namespace[0][1:], name
        return [name]

    @classmethod
    def determine_serialiser_method(
        cls,
        field_alias: str,
        field_info_annotation: type,
        current_element: Any,
        namespaces: dict | None = None,
    ) -> Callable:
        if field_info_annotation is str:
            return str

        if field_info_annotation is datetime:
            return lambda time_val: time_val.isoformat(timespec="milliseconds")

        if field_info_annotation is bool:
            return lambda bool_val: bool_val and "true" or "false"

        if isinstance(field_info_annotation, type) and issubclass(field_info_annotation, BaseElement):
            return functools.partial(
                cls.dump_to_xml,
                clark_name=field_alias,
                parent_element=current_element,
                namespaces=namespaces,
            )

        origin_type = get_origin(field_info_annotation)
        if origin_type is Union or origin_type is types.UnionType:
            for arg in get_args(field_info_annotation):
                method = cls.determine_serialiser_method(field_alias, arg, current_element, namespaces)
                return method

        if origin_type is Annotated:
            annotated_args = get_args(field_info_annotation)
            inner_type, *extras = annotated_args
            if inner_type is bytes:
                if any(
                    isinstance(extra, EncodedBytes) or getattr(extra, "encoder", None) is Base64Encoder
                    for extra in extras
                ):
                    return base64.b64encode
            if isinstance(inner_type, type) and issubclass(inner_type, BaseElement):
                return functools.partial(
                    cls.dump_to_xml,
                    clark_name=field_alias,
                    parent_element=current_element,
                    namespaces=namespaces,
                )

        if get_origin(field_info_annotation) is list:
            (inner_type,) = get_args(field_info_annotation)
            inner_serialiser = cls.determine_serialiser_method(field_alias, inner_type, current_element, namespaces)

            def serialise(values: list[Any] | None):
                if values:
                    for v in values:
                        inner_serialiser(v)

            return serialise

        return str

    def dump_to_xml(
        self,
        clark_name: str,
        parent_element: etree._Element | None = None,
        namespaces: dict | None = None,
    ) -> etree._Element:
        if namespaces is None:
            namespaces = {}

        if parent_element is None:
            current_element = etree.Element(etree.QName(*self.split_clark_tag(clark_name)))
        else:
            current_element = etree.SubElement(parent_element, clark_name, nsmap=namespaces)

        for field_name, field_info in type(self).model_fields.items():

            field_alias = field_info.alias
            if field_alias is None:
                continue

            if field_alias == "*etree_element":
                continue

            content = getattr(self, field_name, None)
            if content is None:
                continue

            if field_info.annotation is None:
                continue

            serialiser = self.determine_serialiser_method(field_alias, field_info.annotation, current_element)
            serialised_content = serialiser(content)

            if field_alias.startswith("@") and serialised_content:
                current_element.attrib[field_alias[1:]] = serialised_content
                continue

            if field_alias == "#text":
                current_element.text = serialised_content
                continue

        for wildcard_element in self.wildcard_content:
            current_element.append(deepcopy(wildcard_element))

        return current_element
