"""WS-I BSP 1.1 R5404 and R5412: only exc-c14n and the SwA content transform are applied, anything else is refused."""

import pytest
from as4.models.dsig.reference import DigestAlgorithm, DigestMethod, DigestValue, Reference, UnsupportedTransform
from as4.models.dsig.transforms import Transform, TransformAlgorithm, Transforms

INCLUSIVE_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"


def reference(*algorithms):
    return Reference(
        transforms=Transforms(transforms=[Transform(algorithm=algorithm) for algorithm in algorithms]),
        digest_method=DigestMethod(algorithm=DigestAlgorithm.SHA256),
        digest_value=DigestValue(text=""),
    )


@pytest.mark.parametrize("algorithms", [(), (INCLUSIVE_C14N,), (TransformAlgorithm.ATTACHMENT_CONTENT_SIGNATURE,)])
def test_an_element_reference_without_exactly_exclusive_c14n_is_refused(algorithms):
    with pytest.raises(UnsupportedTransform):
        reference(*algorithms).digest_matches(reference().dump_to_xml("{http://www.w3.org/2000/09/xmldsig#}Reference"))


@pytest.mark.parametrize("algorithms", [(), (TransformAlgorithm.EXCLUSIVE_C14N,)])
def test_an_attachment_reference_without_the_content_transform_is_refused(algorithms):
    with pytest.raises(UnsupportedTransform):
        reference(*algorithms).digest_matches_bytes(b"payload")
