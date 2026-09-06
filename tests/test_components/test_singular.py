import pytest
from lxml import etree
from as4.models.common import BaseElement, Singular
from pydantic import Field, ValidationError


class Inner(BaseElement):
    value: str = Field(alias="#text")


class Outer(BaseElement):
    inner: Singular[Inner] = Field(alias="{urn:test}Inner")


def test_singular_accepts_one_element():
    element = etree.fromstring(b'<Outer xmlns="urn:test"><Inner>a</Inner></Outer>')
    assert Outer.model_validate_etree(element).inner.value == "a"


def test_singular_rejects_duplicate_elements():
    """Injecting a duplicate element is how signature wrapping starts."""
    element = etree.fromstring(b'<Outer xmlns="urn:test"><Inner>a</Inner><Inner>b</Inner></Outer>')
    with pytest.raises(ValidationError):
        Outer.model_validate_etree(element)
