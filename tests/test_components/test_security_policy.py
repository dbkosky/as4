import pytest
from as4.core.context import SecurityPolicy


def test_defaults_are_strict():
    policy = SecurityPolicy()
    assert policy.sign_required
    assert policy.encrypt_required
    assert policy.verify_digests
    assert policy.required_coverage == frozenset({"messaging", "body", "payloads"})


def test_relaxation_does_not_leak_between_policies():
    relaxed = SecurityPolicy(verify_digests=False)
    assert not relaxed.verify_digests
    assert SecurityPolicy().verify_digests


def test_policy_is_frozen():
    policy = SecurityPolicy()
    with pytest.raises(ValueError):
        policy.verify_digests = False
