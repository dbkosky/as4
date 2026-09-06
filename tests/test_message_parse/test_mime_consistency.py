"""ebMS Core 6.7.1: a header that references a MIME part the message does not carry is EBMS:0007."""

from lxml import etree
from as4.core.context import AS4ParseContext, SecurityPolicy
from as4.core.message import AS4Message
from as4.utils.mime_handler import MIMEHandler

NAMESPACES = {
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "enc": "http://www.w3.org/2001/04/xmlenc#",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
}


def test_a_part_info_naming_no_mime_part_is_refused_with_a_signal(local_party, remote_party, receiving_party, send):
    """Unsigned and unencrypted, so nothing in the security layer notices the missing part first."""
    soap_part, _ = MIMEHandler.parse(MIMEHandler.payload_from_request(*send(local_party, remote_party)))
    envelope = etree.fromstring(soap_part.get_payload(decode=True))
    for xpath in ("//ds:Signature", "//enc:EncryptedKey", "//enc:EncryptedData"):
        for element in envelope.xpath(xpath, namespaces=NAMESPACES):
            element.getparent().remove(element)

    message = AS4Message.parse(
        parse_context=AS4ParseContext(
            local_party=receiving_party,
            security_policy=SecurityPolicy(sign_required=False, encrypt_required=False),
        ),
        soap_bytes=etree.tostring(envelope),
        mime_attachments={},
    )

    assert message.parse_error is not None
    assert message.parse_error.error_code == "EBMS:0007"
    assert "names no MIME part" in message.parse_error.detail
