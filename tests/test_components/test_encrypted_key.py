def test_encrypted_key(expected_encrypted_key_object, example_encrypted_key_object):
    assert example_encrypted_key_object.model_dump() == expected_encrypted_key_object.model_dump()
