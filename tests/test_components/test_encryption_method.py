def test_encrypted_key_encrypted_method(
    expected_encrypted_key_encryption_method_object,
    example_encrypted_key_encryption_method_object,
):
    assert (
        example_encrypted_key_encryption_method_object.model_dump()
        == expected_encrypted_key_encryption_method_object.model_dump()
    )


def test_encrypted_data_encrypted_method(
    expected_encrypted_data_encryption_method_object,
    example_encrypted_data_encryption_method_object,
):
    assert (
        example_encrypted_data_encryption_method_object.model_dump()
        == expected_encrypted_data_encryption_method_object.model_dump()
    )
