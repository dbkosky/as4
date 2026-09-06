def test_security_bst(example_security_object, expected_security_object):
    assert example_security_object.model_dump() == expected_security_object.model_dump()
