import pytest
from as4.errors import BundledMessagesNotSupportedException
from as4.models.ebms.messaging import Messaging


def test_messaging(example_messaging_object, expected_messaging_object):
    assert example_messaging_object.model_dump() == expected_messaging_object.model_dump()


def test_user_message_accessor_returns_none_when_absent():
    assert Messaging().user_message is None


def test_user_message_accessor_returns_the_only_message(expected_messaging_object):
    assert expected_messaging_object.user_message is expected_messaging_object.user_messages[0]


def test_user_message_accessor_rejects_bundling(expected_messaging_object):
    """ebMS 3.0 Core permits one; the Part 2 bundle is not supported."""
    bundled = Messaging(user_messages=expected_messaging_object.user_messages * 2)
    with pytest.raises(BundledMessagesNotSupportedException, match="bundling is not supported"):
        bundled.user_message
