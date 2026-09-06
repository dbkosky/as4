from copy import deepcopy

import pytest
from as4.errors import SignatureCoverageException
from as4.core.common import index_elements_by_id
from as4.core.message import AS4Message
from as4.models.soap.envelope import Envelope
from as4.utils.mime_handler import MIMEHandler
from as4.utils.xml_parser import parse_xml
from tests.assets.test_message import test_as4_mime

REQUIRED = frozenset({"messaging", "body", "payloads"})

soap_part, *_ = MIMEHandler.parse(test_as4_mime)
signed_envelope_element = parse_xml(soap_part.get_payload(decode=True))
elements_by_id = index_elements_by_id(signed_envelope_element)
PAYLOAD_HREFS = set(signed_envelope_element.xpath("//*[local-name()='PartInfo']/@href"))


@pytest.fixture
def signature():
    return Envelope.model_validate_etree(signed_envelope_element).header.security.signature


def without(signature, predicate):
    reduced = deepcopy(signature)
    reduced.signed_info.references = [
        reference for reference in reduced.signed_info.references if not predicate(reference.uri)
    ]
    return reduced


def test_fixture_covers_messaging_body_and_payloads(signature):
    assert AS4Message.signature_coverage(signature, elements_by_id, PAYLOAD_HREFS) == REQUIRED


def test_missing_payload_coverage_is_rejected(signature):
    reduced = without(signature, lambda uri: uri.startswith("cid:"))

    with pytest.raises(SignatureCoverageException) as raised:
        AS4Message.verify_signature_coverage(reduced, elements_by_id, PAYLOAD_HREFS, REQUIRED)

    assert "payloads" in raised.value.detail


def test_missing_body_coverage_is_rejected(signature):
    body_id = Envelope.model_validate_etree(signed_envelope_element).body.body_id
    reduced = without(signature, lambda uri: uri == f"#{body_id}")

    with pytest.raises(SignatureCoverageException) as raised:
        AS4Message.verify_signature_coverage(reduced, elements_by_id, PAYLOAD_HREFS, REQUIRED)

    assert "body" in raised.value.detail


def test_signing_an_unrelated_element_does_not_count_as_coverage(signature):
    """Covering some other wsu:Id'd element must not satisfy a requirement for eb:Messaging."""
    reduced = without(signature, lambda uri: not uri.startswith("cid:"))
    binary_security_token_id = signed_envelope_element.xpath(
        "//*[local-name()='BinarySecurityToken']/@*[local-name()='Id']"
    )[0]
    reduced.signed_info.references[0].uri = f"#{binary_security_token_id}"

    assert AS4Message.signature_coverage(reduced, elements_by_id, PAYLOAD_HREFS) == set()


def test_an_empty_requirement_accepts_anything(signature):
    reduced = without(signature, lambda uri: True)

    AS4Message.verify_signature_coverage(reduced, elements_by_id, PAYLOAD_HREFS, frozenset())


def test_a_declared_payload_that_is_not_signed_is_rejected(signature):
    """Signing one attachment must not vouch for a second the sender also declared."""
    unsigned = PAYLOAD_HREFS | {"cid:unsigned-attachment@cid"}

    with pytest.raises(SignatureCoverageException) as raised:
        AS4Message.verify_signature_coverage(signature, elements_by_id, unsigned, REQUIRED)

    assert "payloads" in raised.value.detail


def test_a_message_declaring_no_payloads_needs_no_payload_coverage(signature):
    """AS4 5.1.5 applies when attachments are present, so an empty PayloadInfo is covered."""
    reduced = without(signature, lambda uri: uri.startswith("cid:"))

    assert "payloads" in AS4Message.signature_coverage(reduced, elements_by_id, set())
