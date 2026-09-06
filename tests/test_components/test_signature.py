def test_signed_info(
    example_signed_info_object,
    expected_signed_info_object,
):
    assert example_signed_info_object.model_dump() == expected_signed_info_object.model_dump()


def test_signature(
    example_signature_object,
    expected_signature_object,
):
    assert example_signature_object.model_dump() == example_signature_object.model_dump()
