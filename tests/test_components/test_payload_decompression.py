import gzip

import pytest
from as4.errors import DecompressedPayloadTooLargeException, DecompressionFailedException
from as4.models.ebms.user_message import PartProperties, Property

GZIPPED = PartProperties(properties=[Property(name="CompressionType", value="application/gzip")])


def test_a_payload_expanding_past_the_budget_is_refused():
    bomb = gzip.compress(b"\0" * (4 * 1024 * 1024))

    with pytest.raises(DecompressedPayloadTooLargeException) as refusal:
        GZIPPED.decompress(decrypted_part_content=bomb, maximum_size=1024)

    assert refusal.value.error_code == "EBMS:0303"
    assert GZIPPED.decompress(decrypted_part_content=gzip.compress(b"invoice"), maximum_size=1024) == b"invoice"


@pytest.mark.parametrize(
    "payload",
    [b"not gzip at all", gzip.compress(b"truncated")[:-4], b"\x1f\x8b\x08\x00" + b"\xff" * 20],
    ids=["no header", "truncated", "corrupt block"],
)
def test_a_payload_that_is_not_valid_gzip_is_refused_with_a_signal(payload):
    with pytest.raises(DecompressionFailedException) as refusal:
        GZIPPED.decompress(decrypted_part_content=payload, maximum_size=1024)

    assert refusal.value.error_code == "EBMS:0303"
