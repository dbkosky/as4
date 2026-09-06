def test_encrypted_key_cipher_data(
    expected_encrypted_key_cipher_data_object,
    example_encrypted_key_cipher_data_object,
):
    assert (
        example_encrypted_key_cipher_data_object.model_dump() == expected_encrypted_key_cipher_data_object.model_dump()
    )


def test_encrypted_data_cipher_data(
    expected_encrypted_data_cipher_data_object,
    example_encrypted_data_cipher_data_object,
):
    assert (
        example_encrypted_data_cipher_data_object.model_dump()
        == expected_encrypted_data_cipher_data_object.model_dump()
    )
