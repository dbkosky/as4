import base64
from copy import deepcopy
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from as4 import const
from cryptography.hazmat.primitives import serialization
from freezegun import freeze_time
from lxml import etree
from as4.core.common import AS4InternalCredentials, AS4InternalParty, AS4PartyIdentity
from as4.core.context import AS4ParseContext, SecurityPolicy
from as4.errors import SignerNotConfiguredError
from as4.core.message import AS4Message
from as4.core.receipt import AS4Receipt
from as4.core.references import AS4References
from as4.core.trust import pinned_certificates
from as4.models.dsig.key_info import KeyInfo
from as4.models.dsig.reference import DigestMethod, DigestValue
from as4.models.dsig.reference import Reference as DsigReference
from as4.models.dsig.signature import CanonicalizationMethod, Signature, SignatureMethod, SignatureValue, SignedInfo
from as4.models.dsig.transforms import Transform as DsigTransform
from as4.models.dsig.transforms import Transforms as DsigTransforms
from as4.models.ebbp.non_repudiation_information import MessagePartNRInformation, NonRepudiationInformation
from as4.models.ebms.description import Description
from as4.models.ebms.message_info import MessageId, MessageInfo, RefToMessageId, Timestamp
from as4.models.ebms.messaging import Messaging
from as4.models.ebms.signal_message import Error, ErrorDetail, Receipt, SignalMessage
from as4.models.soap.header import Header
from as4.models.wsse.binary_security_token import BinarySecurityToken
from as4.models.wsse.security import Security
from as4.models.wsse.security_token_reference import Reference as WsseReference
from as4.models.wsse.security_token_reference import SecurityTokenReference
from as4.utils.mime_handler import MIMEHandler
from tests.assets.test_credentials import test_receiver, test_sender
from tests.assets.test_message import test_as4_mime

LONDON_TIMEZONE = ZoneInfo(key="Europe/London")
TIMEZONE = LONDON_TIMEZONE

DEFAULT_NAMESPACE_MAP = {
    "S12": "http://www.w3.org/2003/05/soap-envelope",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "eb3": "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/",
    "enc": "http://www.w3.org/2001/04/xmlenc#",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
}

REFERENCED_MESSAGE_ID = "00000000-0000-4000-8000-000000000001@as4"

SUCCESS_SIGNATURE_VALUE = (
    b"FzMc0sXSN3zPPRZJpWpadzCKtwLoMyXjzvOpAyBGIB0msQkcPzba8fIuvprA"
    b"ulC/Q5w1lCUJhHLmWHlZZaE94gIShHocq7F8v4W9RDQeAxvKUiZT1KYvxU4m"
    b"xuVf3Lk/5HdU/Uo6ZPZWv1dQWfHhF/Nz1+Ilrw8XJBK6c26jm3Hp2oxnQ4en"
    b"NjLt4uTiXGQRO3WZM2VDq4Qhk25XnFEhrHIUvL9bDxXZg8SPN8OIuft9IAie"
    b"DG64rUvowOetNsrdNhmIm/EU9iKLK/KKZagEJfxO69sa88gjGUa6I40TVYtK"
    b"bfSC8Dfvv0MQIbxJg3/TEUdQR9BfMM01hOijaW2e5Q=="
)

PYDANTIC_VALIDATION_ERROR_SIGNATURE_VALUE = (
    b"J/Xzj6DN0f1rkqr1+1gX2DpOsfIWnFkF0uP+cgt93RCr/27hYAixxRkGDMNp"
    b"KgR99OwILLKkVJ5yEY2Ftapgb10Wn4ID706bCmw6YQIvMvMK1zkffKgLJN82"
    b"cettDIP7LRqX7kG5XAH/9lAwwwXeQm1QYbpVQHaeEeJbrSXdIc3Ug8li20Uz"
    b"JeEvfF73E1vi8JEL4SwjW/ugXcb3fvTuyDbAGa5VC+UmAjunnY73Ww7b67LJ"
    b"0r0ZwIM72muGLoEKXLkp3eWSnYj4PMXiLrpLjQHlvAzW5UsmGzAVDCzQ7aD3"
    b"g1SNO9nA05UpEPGrYQ9HyCG+e/saToVjnLdV10XYdg=="
)


@pytest.fixture
def test_receipt_references() -> AS4References:
    return AS4References(
        message_id="0b85beb5-d317-44e6-80fa-f050e0f8fc04@as4",
        messaging_id="as4-msg-36cc4e49-6e14-47bd-b1b8-bb459dee549b",
        body_id="4e9d1c02-58c3-4a6f-9e1a-7c0d1f3b5a27",
        attachment_id_encrypted_data_id_map={
            "as4-att-dd937d0d-6867-4193-b7b0-b8fc02e26fa1@cid": "ED-e81867d3-b68a-41d5-b541-ba3e92c14be1"
        },
    )


@pytest.fixture
@freeze_time("2025-12-07")
def example_message_info(test_receipt_references) -> AS4References:
    return MessageInfo(
        timestamp=Timestamp(value=datetime.now().replace(tzinfo=TIMEZONE).isoformat()),
        message_id=MessageId(value=test_receipt_references.message_id),
        ref_to_message_id=RefToMessageId(value=REFERENCED_MESSAGE_ID),
    )


@pytest.fixture
def example_security_token_reference(test_receipt_references):
    return SecurityTokenReference(
        security_token_reference_id=test_receipt_references.signature_security_token_reference_id,
        reference=WsseReference(
            uri=f"#{test_receipt_references.signature_bst_id}",
            value_type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
        ),
    )


@pytest.fixture
def example_receiver():
    return AS4InternalParty(
        identity=AS4PartyIdentity(party_id="0208:1111111111", party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
        credentials=AS4InternalCredentials(
            certificate=test_receiver.certificate,
            private_key=test_receiver.private_key,
        ),
    )


@pytest.fixture
def valid_parse_context(example_receiver):
    return AS4ParseContext(
        local_party=example_receiver,
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )


@pytest.fixture
def tampered_parse_context(example_receiver):
    return AS4ParseContext(
        local_party=example_receiver,
        security_policy=SecurityPolicy(
            verify_digests=False,
            signer_resolver=pinned_certificates(test_sender.certificate),
        ),
    )


@pytest.fixture
def example_receiver_certificate_b64(example_receiver):
    return base64.b64encode(example_receiver.credentials.certificate.public_bytes(serialization.Encoding.DER))


@pytest.fixture
def example_binary_security_token(example_receiver_certificate_b64, test_receipt_references):
    return BinarySecurityToken(
        value=example_receiver_certificate_b64,
        encoding_type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary",
        value_type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
        bst_id=test_receipt_references.signature_bst_id,
    )


@freeze_time("2025-12-07")
def test_parse_mime(
    valid_parse_context,
    example_receiver,
    test_receipt_references,
    example_binary_security_token,
    example_message_info,
    example_security_token_reference,
):
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    parsed_message = AS4Message.parse(
        parse_context=valid_parse_context,
        soap_bytes=soap_part.get_payload(decode=True),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )
    expected_receipt = AS4Receipt.for_message(parsed_message, example_receiver, test_receipt_references)
    signature = Signature(
        signature_id=test_receipt_references.signature_id,
        signed_info=SignedInfo(
            canonicalization_method=CanonicalizationMethod(algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"),
            signature_method=SignatureMethod(algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
            references=[
                DsigReference(
                    uri=f"#{test_receipt_references.messaging_id}",
                    transforms=DsigTransforms(
                        transforms=[DsigTransform(algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")]
                    ),
                    digest_method=DigestMethod(algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                    digest_value=DigestValue(text="6AzIvpP6Z19xXhCF/eTr/2q8BI/KhKbdpXgUcPUMzLQ="),
                ),
                DsigReference(
                    uri=f"#{test_receipt_references.body_id}",
                    transforms=DsigTransforms(
                        transforms=[DsigTransform(algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")]
                    ),
                    digest_method=DigestMethod(algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                    digest_value=DigestValue(text="D+2J22kqcnyoU31JG3X0kDvcYFzmH+KZRLCRowIZPz8="),
                ),
            ],
        ),
        signature_value=SignatureValue(value=SUCCESS_SIGNATURE_VALUE),
        key_info=KeyInfo(
            key_info_id=test_receipt_references.key_info_id,
            security_token_reference=[example_security_token_reference],
        ),
    )
    receipt = Receipt(
        non_repudiation_information=NonRepudiationInformation(
            message_part_nr_information=[
                MessagePartNRInformation(
                    references=[
                        DsigReference(
                            uri=f"#{parsed_message.messaging_id}",
                            transforms=DsigTransforms(
                                transforms=[DsigTransform(algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")]
                            ),
                            digest_method=DigestMethod(algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                            digest_value=DigestValue(text="zOz+HWtlAYLqqhZTAWNpOzjcwoarkKls01mRLzvDCU0="),
                        )
                    ]
                ),
                MessagePartNRInformation(
                    references=[
                        DsigReference(
                            uri="#00000000-0000-4000-8000-00000000000d",
                            transforms=DsigTransforms(
                                transforms=[DsigTransform(algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")]
                            ),
                            digest_method=DigestMethod(algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                            digest_value=DigestValue(text="zbyFEqI/g4v4pjaOzePGKpDJS00rkQke3N1HoC4NyKc="),
                        )
                    ]
                ),
                MessagePartNRInformation(
                    references=[
                        DsigReference(
                            uri="cid:as4-att-00000000-0000-4000-8000-00000000000a@cid",
                            transforms=DsigTransforms(
                                transforms=[
                                    DsigTransform(
                                        algorithm=(
                                            "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1"
                                            "#Attachment-Content-Signature-Transform"
                                        )
                                    )
                                ]
                            ),
                            digest_method=DigestMethod(algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                            digest_value=DigestValue(text="D8c8mxvbsl+VMliBlkWJ2sFtxERD/pZCx8NZOc38Bzc="),
                        )
                    ]
                ),
            ],
        )
    )
    example_success_receipt_header = Header(
        security=Security(
            must_understand=True,
            binary_security_tokens=[example_binary_security_token],
            signature=signature,
        ),
        messaging=Messaging(
            messaging_id=test_receipt_references.messaging_id,
            signal_messages=[SignalMessage(message_info=example_message_info, receipt=receipt)],
            w3_org_2003_05_soap_envelope_must_understand=True,
        ),
    )
    assert example_success_receipt_header.model_dump() == expected_receipt.soap_envelope.header.model_dump()


@freeze_time("2025-12-07")
def test_pydantic_validation_exception_handling(
    valid_parse_context,
    example_receiver,
    test_receipt_references,
    example_binary_security_token,
    example_message_info,
    example_security_token_reference,
):
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    soap_bytes = soap_part.get_payload(decode=True)
    soap_envelope_element = etree.fromstring(soap_bytes)
    (key_info,) = soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/wsse:Security/enc:EncryptedKey/ds:KeyInfo",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )
    soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/wsse:Security/enc:EncryptedKey",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0].remove(key_info)
    parsed_message = AS4Message.parse(
        parse_context=valid_parse_context,
        soap_bytes=etree.tostring(soap_envelope_element),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )
    expected_receipt = AS4Receipt.for_message(parsed_message, example_receiver, test_receipt_references)
    signature = Signature(
        signed_info=SignedInfo(
            canonicalization_method=CanonicalizationMethod(algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"),
            signature_method=SignatureMethod(algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
            references=[
                DsigReference(
                    transforms=DsigTransforms(
                        transforms=[DsigTransform(algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")],
                    ),
                    digest_method=DigestMethod(algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                    digest_value=DigestValue(text="IOfYSg5EhjlOZMRVauRhHOETtWWIWwxbyFqOznbfvC8="),
                    uri=f"#{test_receipt_references.messaging_id}",
                ),
                DsigReference(
                    uri=f"#{test_receipt_references.body_id}",
                    transforms=DsigTransforms(
                        transforms=[DsigTransform(algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")]
                    ),
                    digest_method=DigestMethod(algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                    digest_value=DigestValue(text="D+2J22kqcnyoU31JG3X0kDvcYFzmH+KZRLCRowIZPz8="),
                ),
            ],
        ),
        signature_value=SignatureValue(value=PYDANTIC_VALIDATION_ERROR_SIGNATURE_VALUE),
        key_info=KeyInfo(
            key_info_id=test_receipt_references.key_info_id,
            security_token_reference=[example_security_token_reference],
        ),
        signature_id=test_receipt_references.signature_id,
    )
    security = Security(
        binary_security_tokens=[example_binary_security_token],
        signature=signature,
        must_understand=True,
    )
    messaging = Messaging(
        signal_messages=[
            SignalMessage(
                message_info=example_message_info,
                errors=[
                    Error(
                        description=Description(
                            value=(
                                "Although the message document is well formed and schema valid, "
                                "some element/attribute value "
                                "is inconsistent either with the content of other element/attribute, "
                                "or with the processing "
                                "mode of the MSH, or with the normative requirements of the ebMS specification."
                            )
                        ),
                        error_detail=ErrorDetail(
                            value=(
                                "Missing expected content at: "
                                "{http://www.w3.org/2003/05/soap-envelope}Header/"
                                "{http://docs.oasis-open.org/wss/2004/01/"
                                "oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/"
                                "{http://www.w3.org/2001/04/xmlenc#}EncryptedKey/"
                                "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
                            )
                        ),
                        category="Content",
                        ref_to_message_in_error=example_message_info.ref_to_message_id.value,
                        error_code="EBMS:0003",
                        severity="failure",
                        short_description="ValueInconsistent",
                    )
                ],
            )
        ],
        messaging_id=test_receipt_references.messaging_id,
        w3_org_2003_05_soap_envelope_must_understand=True,
    )
    example_pydantic_validation_error_header = Header(
        security=security,
        messaging=messaging,
    )
    assert example_pydantic_validation_error_header.model_dump() == expected_receipt.soap_envelope.header.model_dump()


@freeze_time("2025-12-07")
def test_user_message_not_found_exception_handling(
    valid_parse_context,
    test_receipt_references,
):
    """Missing UserMessage raises MessageIdNotFoundException via pre_validate and generates an error receipt."""
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    soap_bytes = soap_part.get_payload(decode=True)
    soap_envelope_element = etree.fromstring(soap_bytes)

    # Remove UserMessage element - this causes MessageId to not be found
    user_message = soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/eb3:Messaging/eb3:UserMessage",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]
    user_message.getparent().remove(user_message)

    parsed_message = AS4Message.parse(
        parse_context=valid_parse_context,
        soap_bytes=etree.tostring(soap_envelope_element),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    error = parsed_message.parse_error
    assert error is not None
    assert error.error_code == "EBMS:0003"
    assert error.short_description == "ValueInconsistent"
    assert "Missing MessageId" in error.detail


@freeze_time("2025-12-07")
def test_payload_info_not_found_exception_handling(
    tampered_parse_context,
    test_receipt_references,
):
    """Test that missing PayloadInfo raises PayloadInfoNotFoundException and generates error receipt."""
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    soap_bytes = soap_part.get_payload(decode=True)
    soap_envelope_element = etree.fromstring(soap_bytes)

    # Remove PayloadInfo element
    payload_info = soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/eb3:Messaging/eb3:UserMessage/eb3:PayloadInfo",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]
    payload_info.getparent().remove(payload_info)

    parsed_message = AS4Message.parse(
        parse_context=tampered_parse_context,
        soap_bytes=etree.tostring(soap_envelope_element),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    error = parsed_message.parse_error
    assert error is not None
    assert error.error_code == "EBMS:0003"
    assert error.short_description == "ValueInconsistent"
    assert "Missing PayloadInfo" in error.detail

    # A failure after decryption still hands back everything the parse derived.
    message = parsed_message
    assert message.soap_envelope is not None
    user_message = message.soap_envelope.header.messaging.user_message
    assert user_message is not None
    assert user_message.message_info.message_id.value == REFERENCED_MESSAGE_ID
    assert message.mime_attachments == {
        MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)
    }

    (payload,) = parsed_message.decrypted_data.values()
    assert payload.startswith(b"\x1f\x8b")


@freeze_time("2025-12-07")
def test_messaging_not_found_exception_handling(
    valid_parse_context,
    test_receipt_references,
):
    """Test that missing Messaging header raises MessagingNotFoundException and generates error receipt."""
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    soap_bytes = soap_part.get_payload(decode=True)
    soap_envelope_element = etree.fromstring(soap_bytes)

    # Remove Messaging element
    messaging = soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/eb3:Messaging",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]
    messaging.getparent().remove(messaging)

    parsed_message = AS4Message.parse(
        parse_context=valid_parse_context,
        soap_bytes=etree.tostring(soap_envelope_element),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    error = parsed_message.parse_error
    assert error is not None
    assert error.error_code == "EBMS:0003"
    assert error.short_description == "ValueInconsistent"
    assert "Missing ebMS Messaging header" in error.detail


@freeze_time("2025-12-07")
def test_addressed_to_is_parsed_from_party_to_not_party_from(
    example_receiver,
    test_receipt_references,
):
    parse_context = AS4ParseContext(
        local_party=example_receiver,
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)

    message = AS4Message.parse(
        parse_context=parse_context,
        soap_bytes=soap_part.get_payload(decode=True),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    assert message.addressed_to is not None
    assert message.addressed_to.party_id == "0208:1111111111"


@freeze_time("2025-12-07")
def test_party_to_not_found_exception_handling(
    valid_parse_context,
    test_receipt_references,
):
    """Test that missing PartyInfo/To raises PartyToNotFoundException and generates error receipt."""
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    soap_bytes = soap_part.get_payload(decode=True)
    soap_envelope_element = etree.fromstring(soap_bytes)

    # Remove PartyInfo/To element
    party_to = soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/eb3:Messaging/eb3:UserMessage/eb3:PartyInfo/eb3:To",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]
    party_to.getparent().remove(party_to)

    parsed_message = AS4Message.parse(
        parse_context=valid_parse_context,
        soap_bytes=etree.tostring(soap_envelope_element),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    error = parsed_message.parse_error
    assert error is not None
    assert error.error_code == "EBMS:0003"
    assert "Missing PartyInfo/To element" in error.detail


@freeze_time("2025-12-07")
def test_signature_security_token_reference_not_found_exception_handling(
    valid_parse_context,
    test_receipt_references,
):
    """Test that missing SecurityTokenReference URI in Signature reports an authentication failure."""
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    soap_bytes = soap_part.get_payload(decode=True)
    soap_envelope_element = etree.fromstring(soap_bytes)

    ref = soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/wsse:Security/ds:Signature/ds:KeyInfo"
        "/wsse:SecurityTokenReference/wsse:Reference",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]
    del ref.attrib["URI"]

    parsed_message = AS4Message.parse(
        parse_context=valid_parse_context,
        soap_bytes=etree.tostring(soap_envelope_element),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    error = parsed_message.parse_error
    assert error is not None
    assert error.error_code == "EBMS:0101"
    assert error.short_description == "FailedAuthentication"
    assert "SecurityTokenReference URI for Signature" in error.detail


@freeze_time("2025-12-07")
def test_encrypted_key_not_found_exception_handling(
    valid_parse_context,
    test_receipt_references,
):
    """An absent EncryptedKey is a policy violation, not a decryption failure: we asked for encryption."""
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    soap_bytes = soap_part.get_payload(decode=True)
    soap_envelope_element = etree.fromstring(soap_bytes)

    # Remove EncryptedKey element
    encrypted_key = soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/wsse:Security/enc:EncryptedKey",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]
    encrypted_key.getparent().remove(encrypted_key)

    parsed_message = AS4Message.parse(
        parse_context=valid_parse_context,
        soap_bytes=etree.tostring(soap_envelope_element),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    error = parsed_message.parse_error
    assert error is not None
    assert error.error_code == "EBMS:0103"
    assert error.short_description == "PolicyNoncompliance"
    assert "requires encryption" in error.detail


@pytest.fixture
def unpinned_parse_context(example_receiver):
    return AS4ParseContext(
        local_party=example_receiver,
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_receiver.certificate)),
    )


@pytest.fixture
def untrusting_parse_context(example_receiver):
    return AS4ParseContext(local_party=example_receiver)


@freeze_time("2025-12-07")
def test_signer_not_pinned_exception_handling(
    unpinned_parse_context,
    test_receipt_references,
):
    """A certificate the policy does not pin is rejected even though the signature verifies against it."""
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)

    parsed_message = AS4Message.parse(
        parse_context=unpinned_parse_context,
        soap_bytes=soap_part.get_payload(decode=True),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    error = parsed_message.parse_error
    assert error is not None
    assert error.error_code == "EBMS:0101"
    assert error.short_description == "FailedAuthentication"
    assert error.detail == "Signing certificate rejected"


def test_unconfigured_signer_refuses_to_parse(untrusting_parse_context, test_receipt_references):
    """An unset resolver is a local misconfiguration, so it escapes instead of blaming the sender."""
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)

    with pytest.raises(SignerNotConfiguredError):
        AS4Message.parse(
            parse_context=untrusting_parse_context,
            soap_bytes=soap_part.get_payload(decode=True),
            mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
        )


def test_pinned_requires_a_certificate():
    with pytest.raises(ValueError):
        pinned_certificates()


@freeze_time("2025-12-07")
@pytest.mark.parametrize(
    "xpath, error_code, short_description",
    [
        (
            "//wsse:Security/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference",
            "EBMS:0101",
            "FailedAuthentication",
        ),
    ],
)
def test_missing_security_token_reference_uri(
    valid_parse_context,
    test_receipt_references,
    xpath,
    error_code,
    short_description,
):
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    soap_envelope_element = etree.fromstring(soap_part.get_payload(decode=True))
    reference = soap_envelope_element.xpath(xpath, namespaces=DEFAULT_NAMESPACE_MAP)[0]
    del reference.attrib["URI"]

    parsed_message = AS4Message.parse(
        parse_context=valid_parse_context,
        soap_bytes=etree.tostring(soap_envelope_element),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    error = parsed_message.parse_error
    assert error is not None
    assert error.error_code == error_code
    assert error.short_description == short_description


@freeze_time("2025-12-07")
def test_a_signature_with_no_security_token_reference_is_answered_with_a_signal(valid_parse_context):
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    soap_envelope_element = etree.fromstring(soap_part.get_payload(decode=True))
    key_info = soap_envelope_element.xpath(
        "//wsse:Security/ds:Signature/ds:KeyInfo", namespaces=DEFAULT_NAMESPACE_MAP
    )[0]
    key_info.remove(key_info[0])

    parsed_message = AS4Message.parse(
        parse_context=valid_parse_context,
        soap_bytes=etree.tostring(soap_envelope_element),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    error = parsed_message.parse_error
    assert error is not None
    assert error.error_code == "EBMS:0101"


@freeze_time("2025-12-07")
def test_an_encrypted_key_needs_no_security_token_reference_to_be_decrypted(valid_parse_context):
    """The local private key decrypts whatever key identifier the sender chose, so none is required."""
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    soap_envelope_element = etree.fromstring(soap_part.get_payload(decode=True))
    key_info = soap_envelope_element.xpath(
        "//wsse:Security/enc:EncryptedKey/ds:KeyInfo", namespaces=DEFAULT_NAMESPACE_MAP
    )[0]
    key_info.remove(key_info[0])

    parsed_message = AS4Message.parse(
        parse_context=valid_parse_context,
        soap_bytes=etree.tostring(soap_envelope_element),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    assert parsed_message.parse_error is None
    assert parsed_message.decrypted_data


@freeze_time("2025-12-07")
def test_duplicate_element_id_is_rejected_without_digest_verification(
    tampered_parse_context,
    test_receipt_references,
):
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    soap_envelope_element = etree.fromstring(soap_part.get_payload(decode=True))
    token = soap_envelope_element.find(
        "S12:Header/wsse:Security/wsse:BinarySecurityToken",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )
    token.getparent().append(deepcopy(token))

    parsed_message = AS4Message.parse(
        parse_context=tampered_parse_context,
        soap_bytes=etree.tostring(soap_envelope_element),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    error = parsed_message.parse_error
    assert error is not None
    assert error.error_code == "EBMS:0101"
    assert "Duplicate element id" in error.detail


@freeze_time("2025-12-07")
def test_declared_payload_without_signature_coverage_is_rejected(
    tampered_parse_context,
    test_receipt_references,
):
    """A sender must not smuggle in an extra eb:PartInfo the signature never covered."""
    soap_part, encrypted_part = MIMEHandler.parse(test_as4_mime)
    soap_envelope_element = etree.fromstring(soap_part.get_payload(decode=True))
    part_info = soap_envelope_element.find(
        "S12:Header/eb3:Messaging/eb3:UserMessage/eb3:PayloadInfo/eb3:PartInfo",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )
    smuggled = deepcopy(part_info)
    smuggled.set("href", "cid:smuggled-attachment@cid")
    part_info.getparent().append(smuggled)

    parsed_message = AS4Message.parse(
        parse_context=tampered_parse_context,
        soap_bytes=etree.tostring(soap_envelope_element),
        mime_attachments={MIMEHandler.get_content_id(encrypted_part): encrypted_part.get_payload(decode=True)},
    )

    error = parsed_message.parse_error
    assert error is not None
    assert error.error_code == "EBMS:0101"
    assert "payloads" in error.detail
