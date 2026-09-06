from copy import deepcopy

import pytest
from lxml import etree
from as4.errors import DuplicateElementIdException
from as4.core.common import index_elements_by_id
from as4.models.dsig.reference import Reference
from as4.models.soap.envelope import Envelope
from as4.utils.mime_handler import MIMEHandler
from tests.assets.test_message import test_as4_mime

soap_part, *_ = MIMEHandler.parse(test_as4_mime)
signed_envelope_element = etree.fromstring(soap_part.get_payload(decode=True))

PREFIXED_ENVELOPE = b"""<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
 xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
 xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
<eb:Messaging wsu:Id="messaging-1"><eb:SignalMessage/></eb:Messaging></S12:Envelope>"""

REFERENCE_TEMPLATE = """<ds:Reference xmlns:ds="http://www.w3.org/2000/09/xmldsig#" URI="#messaging-1">
  <ds:Transforms>
    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">{inclusive}</ds:Transform>
  </ds:Transforms>
  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
  <ds:DigestValue>unused</ds:DigestValue>
</ds:Reference>"""

INCLUSIVE_NAMESPACES = '<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="S12"/>'


def build_reference(inclusive: str) -> Reference:
    return Reference.model_validate_etree(etree.fromstring(REFERENCE_TEMPLATE.format(inclusive=inclusive)))


def resolve_in(root, uri):
    return index_elements_by_id(root)[uri.removeprefix("#")]


@pytest.fixture
def signature():
    return Envelope.model_validate_etree(signed_envelope_element).header.security.signature


def test_signed_message_digests_verify(signature):
    """cid: references digest attachment octets, which AS4Message.verify_attachment_digests covers."""
    references = [reference for reference in signature.signed_info.references if not reference.uri.startswith("cid:")]
    assert len(references) == 2
    for reference in references:
        assert reference.digest_matches(resolve_in(signed_envelope_element, reference.uri))


def test_tampering_breaks_the_digest(signature):
    reference = signature.signed_info.references[0]
    tampered = deepcopy(resolve_in(signed_envelope_element, reference.uri))
    tampered.set("tampered", "true")
    assert not reference.digest_matches(tampered)


def test_inclusive_namespace_prefixes_change_the_digest():
    """Exclusive c14n drops xmlns:S12 unless the PrefixList names it."""
    target = resolve_in(etree.fromstring(PREFIXED_ENVELOPE), "#messaging-1")

    assert build_reference(INCLUSIVE_NAMESPACES).inclusive_namespaces == ["S12"]
    assert build_reference("").inclusive_namespaces == []
    assert build_reference(INCLUSIVE_NAMESPACES).digest(target) != build_reference("").digest(target)


def test_duplicate_element_id_is_rejected(signature):
    envelope = etree.fromstring(etree.tostring(signed_envelope_element))
    target = resolve_in(envelope, signature.signed_info.references[0].uri)
    target.getparent().append(deepcopy(target))

    with pytest.raises(DuplicateElementIdException):
        index_elements_by_id(envelope)
