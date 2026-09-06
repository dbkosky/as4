"""The ebMS 3.0 schema is looser than the model used to be. These are the shapes it allows."""

import pytest
from as4.errors import BaseAS4ReceiptableError, BundledMessagesNotSupportedException
from as4.utils.xml_parser import parse_xml
from as4.models.ebms.messaging import Messaging
from pydantic_core import ValidationError
from as4.models.ebms.signal_message import SignalMessage

EB3 = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
EBBP = "http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0"

MESSAGE_INFO = """
  <eb3:MessageInfo>
    <eb3:Timestamp>2026-01-01T00:00:00Z</eb3:Timestamp>
    <eb3:MessageId>signal@as4</eb3:MessageId>
    <eb3:RefToMessageId>original@as4</eb3:RefToMessageId>
  </eb3:MessageInfo>
"""


def signal(body: str) -> SignalMessage:
    xml = f'<eb3:SignalMessage xmlns:eb3="{EB3}" xmlns:ebbp="{EBBP}">{MESSAGE_INFO}{body}</eb3:SignalMessage>'
    return SignalMessage.model_validate_etree(parse_xml(xml.encode()))


def test_a_receipt_without_non_repudiation_information_parses():
    parsed = signal("<eb3:Receipt>" "<eb3:UserMessage><eb3:MessageInfo/></eb3:UserMessage>" "</eb3:Receipt>")

    assert parsed.receipt is not None
    assert parsed.receipt.non_repudiation_information is None


def test_a_non_repudiation_receipt_still_parses():
    parsed = signal("<eb3:Receipt>" "<ebbp:NonRepudiationInformation/>" "</eb3:Receipt>")

    assert parsed.receipt is not None
    assert parsed.receipt.non_repudiation_information is not None


def test_a_signal_carrying_a_series_of_errors_parses():
    """eb:Error is maxOccurs=unbounded, so a signal may report several faults at once."""
    parsed = signal(
        '<eb3:Error errorCode="EBMS:0003" severity="failure"/>' '<eb3:Error errorCode="EBMS:0009" severity="failure"/>'
    )

    assert [error.error_code for error in parsed.errors] == ["EBMS:0003", "EBMS:0009"]
    assert parsed.error is not None
    assert parsed.error.error_code == "EBMS:0003"


def test_a_signal_carrying_no_error_reports_none():
    parsed = signal("")

    assert parsed.errors == []
    assert parsed.error is None


def test_bundling_is_refused_with_a_receiptable_error():
    """Bundling is legal in ebMS Part 2 and unsupported here: EBMS:0002, not an invalid header."""
    one = signal('<eb3:Error errorCode="EBMS:0003" severity="failure"/>')
    bundled = Messaging(signal_messages=[one, one])

    with pytest.raises(BundledMessagesNotSupportedException) as raised:
        bundled.signal_message

    assert raised.value.error_code == "EBMS:0002"
    assert "found 2 eb:SignalMessage elements" in str(raised.value)


def test_a_repeated_header_element_is_reported_as_an_invalid_header():
    """exactly_one surfaces as a pydantic error; a repeated element is EBMS:0009, not EBMS:0003."""
    xml = f'<eb3:SignalMessage xmlns:eb3="{EB3}">' "<eb3:MessageInfo/><eb3:MessageInfo/>" "</eb3:SignalMessage>"
    with pytest.raises(ValidationError) as raised:
        SignalMessage.model_validate_etree(parse_xml(xml.encode()))

    reported = BaseAS4ReceiptableError.from_validation_error(raised.value)

    assert reported.error_code == "EBMS:0009"
    assert "MessageInfo" in reported.detail


def test_missing_content_is_still_reported_as_value_inconsistent():
    xml = f'<eb3:SignalMessage xmlns:eb3="{EB3}"/>'
    with pytest.raises(ValidationError) as raised:
        SignalMessage.model_validate_etree(parse_xml(xml.encode()))

    reported = BaseAS4ReceiptableError.from_validation_error(raised.value)

    assert reported.error_code == "EBMS:0003"
