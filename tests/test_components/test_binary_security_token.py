def test_signing_bst(
    expected_signing_binary_security_token_object,
    example_signing_binary_security_token_object,
):
    assert (
        example_signing_binary_security_token_object.model_dump()
        == expected_signing_binary_security_token_object.model_dump()
    )


def test_encryption_bst(
    expected_encryption_binary_security_token_object,
    example_encryption_binary_security_token_object,
):
    assert (
        example_encryption_binary_security_token_object.model_dump()
        == expected_encryption_binary_security_token_object.model_dump()
    )
