"""Regenerate the committed AS4 artefacts: python -m tests.assets.test_message.generate

Identifiers below are pinned, but the timestamp, the gzip mtime and the random AES and OAEP
material are not, so every digest, cipher value and signature changes on each run. The recorded
copies in tests/test_components/conftest.py and tests/test_message_parse/test_parse.py have to be
refreshed from the new artefacts afterwards.
"""

from pathlib import Path

from as4.core.references import AS4References
from as4.profiles.peppol.profile import (
    build_peppol_message,
    create_peppol_external_party,
    create_peppol_internal_party,
)
from as4.utils.mime_handler import MIMEHandler
from tests.assets.test_credentials import test_receiver, test_sender

SENDING_AP_ID = "0208:9999999999"
RECEIVING_AP_ID = "0208:1111111111"
DOCUMENT_TYPE_IDENTIFIER = (
    "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice"
    "##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1"
)
INSTANCE_IDENTIFIER = "00000000-0000-4000-8000-00000000000c"
ATTACHMENT_ID = "as4-att-00000000-0000-4000-8000-00000000000a@cid"
ENCRYPTED_DATA_ID = "ED-00000000-0000-4000-8000-00000000000b"


def fixed_references() -> AS4References:
    """Identifiers are pinned so regenerating does not invalidate every id asserted in the suite."""
    return AS4References(
        message_id="00000000-0000-4000-8000-000000000001@as4",
        messaging_id="as4-msg-00000000-0000-4000-8000-000000000002",
        conversation_id="as4@00000000-0000-4000-8000-000000000003",
        encrypted_key_bst_id="00000000-0000-4000-8000-000000000004",
        signature_bst_id="X509-00000000-0000-4000-8000-000000000005",
        encrypted_key_id="EK-00000000-0000-4000-8000-000000000006",
        signature_id="SIG-00000000-0000-4000-8000-000000000007",
        key_info_id="KI-00000000-0000-4000-8000-000000000008",
        signature_security_token_reference_id="STR-00000000-0000-4000-8000-000000000009",
        body_id="00000000-0000-4000-8000-00000000000d",
        attachment_id_encrypted_data_id_map={ATTACHMENT_ID: ENCRYPTED_DATA_ID},
    )


def build() -> bytes:
    message = build_peppol_message(
        payload=b'<Invoice xmlns="urn:test">payload</Invoice>',
        local_party=create_peppol_internal_party(SENDING_AP_ID, test_sender.certificate, test_sender.private_key),
        remote_party=create_peppol_external_party(RECEIVING_AP_ID, test_receiver.certificate),
        sender="9999999999",
        recipient="1111111111",
        document_type_identifier_scheme="busdox-docid-qns",
        document_type_identifier_value=DOCUMENT_TYPE_IDENTIFIER,
        process_identifier="urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
        sender_country_id="BE",
        document_identification_instance_identifier=INSTANCE_IDENTIFIER,
        references=fixed_references(),
    )
    request_body, boundary = message.get_request_data()
    return MIMEHandler.payload_from_request(message.get_http_headers(boundary), request_body)


def main() -> None:
    here = Path(__file__).parent
    request_payload = build()
    soap_part, _encrypted_part = MIMEHandler.parse(request_payload)

    (here / "test_as4.mime").write_bytes(request_payload)
    (here / "test_soap_envelope.xml").write_bytes(soap_part.get_payload(decode=True))


if __name__ == "__main__":
    main()
