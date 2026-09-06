import base64
import hashlib
from enum import StrEnum
from typing import Callable, Self

from lxml import etree
from as4.models.common import BaseElement, Singular, Sorted
from pydantic import BaseModel, ConfigDict, Field

from .transforms import Transform, TransformAlgorithm, Transforms


class DigestAlgorithm(StrEnum):
    SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
    SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"


DIGEST_ALGORITHM_MAP: dict[str, Callable[[bytes], "hashlib._Hash"]] = {
    DigestAlgorithm.SHA256: hashlib.sha256,
    DigestAlgorithm.SHA384: hashlib.sha384,
    DigestAlgorithm.SHA512: hashlib.sha512,
}


class UnsupportedDigestAlgorithm(Exception):
    """A reference names a digest algorithm outside the set this library will verify."""


class UnsupportedTransform(Exception):
    """A signature names a transform or canonicalisation outside the set this library will apply."""


class DigestMethod(BaseElement):

    algorithm: str = Field(alias="@Algorithm")


class DigestValue(BaseElement):
    text: str = Field(alias="#text")


class Reference(BaseElement):
    transforms: Singular[Transforms] = Field(alias="{http://www.w3.org/2000/09/xmldsig#}Transforms")
    digest_method: Singular[DigestMethod] = Field(alias="{http://www.w3.org/2000/09/xmldsig#}DigestMethod")
    digest_value: Singular[DigestValue] = Field(alias="{http://www.w3.org/2000/09/xmldsig#}DigestValue")
    id: str | None = Field(default=None, alias="@Id")
    uri: str | None = Field(default=None, alias="@URI")
    type_value: str | None = Field(default=None, alias="@Type")

    @property
    def inclusive_namespaces(self) -> list[str]:
        for transform in self.transforms.transforms:
            if transform.algorithm == TransformAlgorithm.EXCLUSIVE_C14N:
                return transform.inclusive_namespaces
        return []

    @classmethod
    def compute_digest(cls, digest_algorithm: str, content: bytes) -> str:
        digest_func = DIGEST_ALGORITHM_MAP.get(digest_algorithm)
        if digest_func is None:
            raise UnsupportedDigestAlgorithm(digest_algorithm)
        return base64.b64encode(digest_func(content).digest()).decode()

    @classmethod
    def canonicalize(cls, element: etree._Element, inclusive_ns_prefixes: list[str]) -> bytes:
        return etree.tostring(
            element,
            method="c14n",
            exclusive=True,
            with_comments=False,
            inclusive_ns_prefixes=inclusive_ns_prefixes,
        )

    @classmethod
    def for_element(cls, uri: str, element: etree._Element, digest_algorithm: DigestAlgorithm) -> Self:
        return cls(
            transforms=Transforms(transforms=[Transform(algorithm=TransformAlgorithm.EXCLUSIVE_C14N)]),
            digest_method=DigestMethod(algorithm=digest_algorithm),
            digest_value=DigestValue(text=cls.compute_digest(digest_algorithm, cls.canonicalize(element, []))),
            uri=uri,
        )

    @classmethod
    def for_bytes(
        cls,
        uri: str,
        content: bytes,
        digest_algorithm: DigestAlgorithm,
        transform_algorithm: TransformAlgorithm,
    ) -> Self:
        return cls(
            transforms=Transforms(transforms=[Transform(algorithm=transform_algorithm)]),
            digest_method=DigestMethod(algorithm=digest_algorithm),
            digest_value=DigestValue(text=cls.compute_digest(digest_algorithm, content)),
            uri=uri,
        )

    def digest_bytes(self, content: bytes) -> str:
        return self.compute_digest(self.digest_method.algorithm, content)

    def digest(self, element: etree._Element) -> str:
        return self.digest_bytes(self.canonicalize(element, self.inclusive_namespaces))

    def require_transforms(self, allowed: set[str]) -> None:
        algorithms = {transform.algorithm for transform in self.transforms.transforms}
        if not algorithms or not algorithms <= allowed:
            raise UnsupportedTransform(", ".join(sorted(str(algorithm) for algorithm in algorithms)) or "none")

    def digest_matches(self, element: etree._Element) -> bool:
        self.require_transforms({TransformAlgorithm.EXCLUSIVE_C14N})
        return self.digest(element) == self.digest_value.text.strip()

    def digest_matches_bytes(self, content: bytes) -> bool:
        self.require_transforms({TransformAlgorithm.ATTACHMENT_CONTENT_SIGNATURE})
        return self.digest_bytes(content) == self.digest_value.text.strip()


class ComparableReferenceFields(BaseModel):
    model_config = ConfigDict(frozen=True)

    uri: str
    transform_algorithms: Sorted = Field(default_factory=list)
    digest_algorithm: str
    digest_value: str

    @classmethod
    def from_reference(cls, reference: Reference) -> "ComparableReferenceFields":
        return cls(
            uri=reference.uri or "",
            transform_algorithms=[
                transform.algorithm for transform in reference.transforms.transforms if transform.algorithm
            ],
            digest_algorithm=reference.digest_method.algorithm,
            digest_value=reference.digest_value.text.strip(),
        )
