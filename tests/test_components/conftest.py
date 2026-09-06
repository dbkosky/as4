from datetime import datetime

import pytest
from as4.models.dsig.key_info import KeyInfo
from as4.models.dsig.reference import DigestMethod, DigestValue
from as4.models.dsig.reference import Reference as DsigReference
from as4.models.dsig.signature import CanonicalizationMethod, Signature, SignatureMethod, SignatureValue, SignedInfo
from as4.models.dsig.transforms import Transform as DsigTransform
from as4.models.dsig.transforms import Transforms as DsigTransforms
from as4.models.ebms.message_info import MessageId, MessageInfo, Timestamp
from as4.models.ebms.messaging import Messaging
from as4.models.ebms.user_message import (
    Action,
    AgreementRef,
    CollaborationInfo,
    ConversationId,
    MessageProperties,
    PartInfo,
    PartProperties,
    PartyFrom,
    PartyId,
    PartyInfo,
    PartyTo,
    PayloadInfo,
    Property,
    Role,
    Service,
    UserMessage,
)
from as4.models.wsse.binary_security_token import BinarySecurityToken
from as4.models.wsse.security import Security
from as4.models.wsse.security_token_reference import Reference as WsseReference
from as4.models.wsse.security_token_reference import SecurityTokenReference
from as4.models.xenc.encrypted_type import (
    MGF,
    CipherData,
    CipherReference,
    CipherValue,
    EncryptedKey,
    EncryptedType,
    EncryptionMethod,
)
from as4.models.xenc.encrypted_type import Transforms as XencTransforms
from as4.models.xenc.reference import Reference as XencReference
from as4.models.xenc.reference import ReferenceList
from tests.assets.test_message import test_soap_envelope_element

DEFAULT_NAMESPACE_MAP = {
    "S11": "http://schemas.xmlsoap.org/soap/envelope/",
    "S12": "http://www.w3.org/2003/05/soap-envelope",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "eb": "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/",
    "enc": "http://www.w3.org/2001/04/xmlenc#",
    "wsr": "http://docs.oasis-open.org/wsrm/2004/06/ws-reliability-1.1.xsd",
    "wsrx": "http://docs.oasis-open.org/ws-rx/wsrm/200702",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
    "ebbpsig": "http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0",
    "xenc11": "http://www.w3.org/2009/xmlenc11#",
}

SIGNATURE_BINARY_SECURITY_TOKEN_ID = "X509-00000000-0000-4000-8000-000000000005"
ENCRYPTION_BINARY_SECURITY_TOKEN_ID = "00000000-0000-4000-8000-000000000004"
ENCRYPTED_KEY_ID = "EK-00000000-0000-4000-8000-000000000006"
ENCRYPTED_DATA_ID = "ED-00000000-0000-4000-8000-00000000000b"
MESSAGING_ID = "as4-msg-00000000-0000-4000-8000-000000000002"
MESSAGE_ID = "00000000-0000-4000-8000-000000000001@as4"
CONVERSATION_ID = "as4@00000000-0000-4000-8000-000000000003"
ATTACHMENT_PART_URI = "cid:as4-att-00000000-0000-4000-8000-00000000000a@cid"
SIGNATURE_ID = "SIG-00000000-0000-4000-8000-000000000007"
SECURITY_TOKEN_REFERENCE_ID = "STR-00000000-0000-4000-8000-000000000009"
SIGNATURE_KEY_INFO_ID = "KI-00000000-0000-4000-8000-000000000008"

CIPHER_VALUE_B64 = (
    "iKhgWhJoVBvJ6iYsx37wM9LibbBvtgBboOZlFCqLCjSrh0AcW7WUzj502JusktksjqF88jOc"
    "uy7QcGPgoEyHCveCQrdt/gj2xP4VpXUeMNGKETxHXk9NHMg5Zu1UNCwM8WX4zd1O3+Cye5cz"
    "gIwTWl/zG3F0/zWsEH3mOUnHCeSqoaY9WvLXfPTcftjZQ3TPMGAbrHzk+VM8783Bt2YRc2pB"
    "Q/r7hKrI0HU9p7hU/Gs7cb8dFho7ivYTCeOnikQhdChm1F+aZecZ22zs9dIozciSnYLpHzX4"
    "5pfCyYKUVDQcj5uUiN/orMLp8x47Ue0LDN3XsEQ2tjLCgFTDgl7m0A=="
)

SIGNATURE_VALUE_B64 = (
    "CbCrx8Px3UxaUlvcUgZwxuU+/faTkG3fTTvXNTENUowqvcbOwvYiT0TJZPqE9No0u4Fpb5lR"
    "2NQgAALOXKhK8lI97E8Q7UbD7mb40xHj1fp/wQQfWtvM+pzFvNhrxgEq/U+L6lZEJIq37bFv"
    "9/48AzUQRC1UcyZDnuZVTnqUqcuNvQ4lLr3O2CchqFM/WW9wZMgCB1lgjZ8AlgQMThtrfYjG"
    "EEyHXZb9iA09XNk67m6bg2VSBRc9LjMIvsAOJL9v8dL5unpeoHocaZtnuVckZt5NETXR8adt"
    "gypW1ATLzjl+pAKGeamEamyzreIvKy3KWQ/YU+o7j4PIRxSHUGY45w=="
)
DIGEST_VALUE_B64 = "uj2Ry++nML3iJIt/ief4geidT2AFu+7EQhqP4bt2iU0="
BODY_ID = "00000000-0000-4000-8000-00000000000d"
BODY_DIGEST_VALUE_B64 = "zbyFEqI/g4v4pjaOzePGKpDJS00rkQke3N1HoC4NyKc="
ATTACHMENT_DIGEST_VALUE_B64 = "VKsT8tj9KhUk9g0XQUTzDKMj+9uCczOclTjbosG51DI="
MESSAGE_TIMESTAMP = test_soap_envelope_element.xpath(
    "//eb:UserMessage/eb:MessageInfo/eb:Timestamp/text()", namespaces=DEFAULT_NAMESPACE_MAP
)[0]


@pytest.fixture
def expected_signed_info_element():
    """XML element for expected signed info"""
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/wsse:Security/ds:Signature/ds:SignedInfo",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]


@pytest.fixture
def expected_signed_info_object(expected_signed_info_element):
    """Expected signed info object from XML"""
    return SignedInfo.model_validate_etree(expected_signed_info_element)


@pytest.fixture
def example_signed_info_object(expected_signed_info_element):
    """Example signed info object for testing"""
    return SignedInfo(
        canonicalization_method=CanonicalizationMethod(algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"),
        signature_method=SignatureMethod(algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
        references=[
            DsigReference(
                transforms=DsigTransforms(
                    transforms=[DsigTransform(algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")]
                ),
                uri=f"#{MESSAGING_ID}",
                digest_method=DigestMethod(algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                digest_value=DigestValue(text=DIGEST_VALUE_B64),
            ),
            DsigReference(
                transforms=DsigTransforms(
                    transforms=[DsigTransform(algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")]
                ),
                uri=f"#{BODY_ID}",
                digest_method=DigestMethod(algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                digest_value=DigestValue(text=BODY_DIGEST_VALUE_B64),
            ),
            DsigReference(
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
                uri=ATTACHMENT_PART_URI,
                digest_method=DigestMethod(algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                digest_value=DigestValue(text=ATTACHMENT_DIGEST_VALUE_B64),
            ),
        ],
    )


@pytest.fixture
def example_signature_object(
    example_signature_key_info_object,
    example_signed_info_object,
):
    """Example signature object for testing"""
    return Signature(
        signed_info=example_signed_info_object,
        signature_value=SignatureValue(value=SIGNATURE_VALUE_B64),
        key_info=example_signature_key_info_object,
        signature_id=SIGNATURE_ID,
    )


@pytest.fixture
def example_signature_key_info_object():
    """Fixture for signature key info object"""
    reference = WsseReference(
        uri=f"#{SIGNATURE_BINARY_SECURITY_TOKEN_ID}",
        value_type=("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-" "token-profile-1.0#X509v3"),
    )
    signature_token_reference = SecurityTokenReference(
        reference=reference,
        security_token_reference_id=SECURITY_TOKEN_REFERENCE_ID,
    )
    return KeyInfo(
        key_info_id=SIGNATURE_KEY_INFO_ID,
        security_token_reference=[signature_token_reference],
    )


@pytest.fixture
def example_encrypted_key_encryption_method_object():
    """Fixture for encrypted key encryption method"""
    return EncryptionMethod(
        algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep",
        digest_method=DigestMethod(algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
        mgf=MGF(algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"),
    )


@pytest.fixture
def example_security_key_info_object():
    """Fixture for security key info object"""
    reference = WsseReference(
        uri=f"#{ENCRYPTION_BINARY_SECURITY_TOKEN_ID}",
        value_type=("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-" "token-profile-1.0#X509v3"),
    )
    security_token_reference = SecurityTokenReference(
        reference=reference,
    )
    return KeyInfo(
        key_info_id=None,
        security_token_reference=[security_token_reference],
    )


@pytest.fixture
def example_encrypted_key_cipher_data_object():
    """Fixture for encrypted key cipher data"""
    return CipherData(
        cipher_value=CipherValue(value=CIPHER_VALUE_B64),
    )


@pytest.fixture
def example_encrypted_data_encryption_method_object():
    """Fixture for encrypted data encryption method"""
    return EncryptionMethod(algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm")


@pytest.fixture
def example_encrypted_data_key_info_object():
    """Fixture for encrypted data key info object"""
    return KeyInfo(
        security_token_reference=[
            SecurityTokenReference(
                token_type=("http://docs.oasis-open.org/wss/oasis-wss-soap-message-" "security-1.1#EncryptedKey"),
                reference=WsseReference(
                    uri=f"#{ENCRYPTED_KEY_ID}",
                ),
            )
        ]
    )


@pytest.fixture
def example_encrypted_data_cipher_data_object():
    """Fixture for encrypted data cipher data object"""
    return CipherData(
        cipher_reference=CipherReference(
            uri=ATTACHMENT_PART_URI,
            transforms=XencTransforms(
                transforms=[
                    DsigTransform(
                        algorithm=(
                            "http://docs.oasis-open.org/wss/oasis-wss-"
                            "SwAProfile-1.1#Attachment-Ciphertext-Transform"
                        )
                    )
                ]
            ),
        )
    )


# Security fixtures
@pytest.fixture
def expected_security_element():
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/wsse:Security",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]


@pytest.fixture
def expected_security_object(expected_security_element):
    return Security.model_validate_etree(expected_security_element)


@pytest.fixture
def example_encrypted_key_object(example_encrypted_key_encryption_method_object):
    encryption_token_reference = SecurityTokenReference(
        reference=WsseReference(
            uri=f"#{ENCRYPTION_BINARY_SECURITY_TOKEN_ID}",
            value_type=("http://docs.oasis-open.org/wss/2004/01/oasis-200401" "-wss-x509-token-profile-1.0#X509v3"),
        ),
    )
    return EncryptedKey(
        encrypted_type_id=ENCRYPTED_KEY_ID,
        encryption_method=example_encrypted_key_encryption_method_object,
        key_info=KeyInfo(
            security_token_reference=[encryption_token_reference],
        ),
        cipher_data=CipherData(
            cipher_value=CipherValue(value=CIPHER_VALUE_B64),
        ),
        reference_list=ReferenceList(data_reference=[XencReference(uri=f"#{ENCRYPTED_DATA_ID}")]),
    )


@pytest.fixture
def example_encrypted_data_object(example_encrypted_data_encryption_method_object):
    data_token_reference = SecurityTokenReference(
        reference=WsseReference(
            uri="#" + ENCRYPTED_KEY_ID,
        ),
        token_type=("http://docs.oasis-open.org/wss/oasis-wss-soap" "-message-security-1.1#EncryptedKey"),
    )
    dsig_transforms = [
        DsigTransform(
            algorithm="http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform"
        )
    ]

    return EncryptedType(
        encrypted_type_id=ENCRYPTED_DATA_ID,
        type_value=("http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1" "#Attachment-Content-Only"),
        mime_type="application/gzip",
        encryption_method=example_encrypted_data_encryption_method_object,
        key_info=KeyInfo(
            security_token_reference=[data_token_reference],
        ),
        cipher_data=CipherData(
            cipher_reference=CipherReference(
                uri=ATTACHMENT_PART_URI,
                transforms=XencTransforms(
                    transforms=dsig_transforms,
                ),
            ),
        ),
    )


@pytest.fixture
def example_security_object(
    example_signing_binary_security_token_object,
    example_encryption_binary_security_token_object,
    example_encrypted_key_object,
    example_encrypted_data_object,
    example_signature_object,
):
    return Security(
        binary_security_tokens=[
            example_encryption_binary_security_token_object,
            example_signing_binary_security_token_object,
        ],
        encrypted_key=example_encrypted_key_object,
        encrypted_data=[example_encrypted_data_object],
        signature=example_signature_object,
        must_understand=True,
    )


# Binary Security Token fixtures and constants
ENCRYPTION_BINARY_SECURITY_TOKEN_XPATH = f"""
//S12:Envelope/S12:Header/wsse:Security/wsse:BinarySecurityToken[@wsu:Id="{ENCRYPTION_BINARY_SECURITY_TOKEN_ID}"]
"""
SIGNATURE_BINARY_SECURITY_TOKEN_XPATH = f"""
//S12:Envelope/S12:Header/wsse:Security/wsse:BinarySecurityToken[@wsu:Id="{SIGNATURE_BINARY_SECURITY_TOKEN_ID}"]
"""

# Extract certificate values directly from test message XML
encryption_cert_element = test_soap_envelope_element.xpath(
    f'//wsse:BinarySecurityToken[@wsu:Id="{ENCRYPTION_BINARY_SECURITY_TOKEN_ID}"]', namespaces=DEFAULT_NAMESPACE_MAP
)[0]
sender_certificate_b64 = encryption_cert_element.text

signature_cert_element = test_soap_envelope_element.xpath(
    f'//wsse:BinarySecurityToken[@wsu:Id="{SIGNATURE_BINARY_SECURITY_TOKEN_ID}"]', namespaces=DEFAULT_NAMESPACE_MAP
)[0]
receiver_certificate_b64 = signature_cert_element.text


@pytest.fixture
def expected_signing_binary_security_token_element():
    return test_soap_envelope_element.xpath(SIGNATURE_BINARY_SECURITY_TOKEN_XPATH, namespaces=DEFAULT_NAMESPACE_MAP)[0]


@pytest.fixture
def expected_signing_binary_security_token_object(expected_signing_binary_security_token_element):
    return BinarySecurityToken.model_validate_etree(expected_signing_binary_security_token_element)


@pytest.fixture
def expected_encryption_binary_security_token_element():
    return test_soap_envelope_element.xpath(ENCRYPTION_BINARY_SECURITY_TOKEN_XPATH, namespaces=DEFAULT_NAMESPACE_MAP)[
        0
    ]


@pytest.fixture
def expected_encryption_binary_security_token_object(expected_encryption_binary_security_token_element):
    return BinarySecurityToken.model_validate_etree(expected_encryption_binary_security_token_element)


# Additional expected fixtures for all the missing elements
@pytest.fixture
def expected_encrypted_key_element():
    xpath_query = f"//S12:Envelope/S12:Header/wsse:Security/enc:EncryptedKey" f"[@Id='{ENCRYPTED_KEY_ID}']"
    return test_soap_envelope_element.xpath(xpath_query, namespaces=DEFAULT_NAMESPACE_MAP)[0]


@pytest.fixture
def expected_encrypted_key_object(expected_encrypted_key_element):
    return EncryptedKey.model_validate_etree(expected_encrypted_key_element)


@pytest.fixture
def expected_encrypted_data_element():
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/wsse:Security/enc:EncryptedData", namespaces=DEFAULT_NAMESPACE_MAP
    )[0]


@pytest.fixture
def expected_encrypted_data_object(expected_encrypted_data_element):
    return EncryptedType.model_validate_etree(expected_encrypted_data_element)


@pytest.fixture
def expected_encrypted_key_cipher_data_element():
    xpath_query = (
        f"//S12:Envelope/S12:Header/wsse:Security/enc:EncryptedKey" f"[@Id='{ENCRYPTED_KEY_ID}']/enc:CipherData"
    )
    return test_soap_envelope_element.xpath(xpath_query, namespaces=DEFAULT_NAMESPACE_MAP)[0]


@pytest.fixture
def expected_encrypted_key_cipher_data_object(
    expected_encrypted_key_cipher_data_element,
):
    return CipherData.model_validate_etree(expected_encrypted_key_cipher_data_element)


@pytest.fixture
def expected_encrypted_data_cipher_data_element():
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/wsse:Security/enc:EncryptedData/enc:CipherData", namespaces=DEFAULT_NAMESPACE_MAP
    )[0]


@pytest.fixture
def expected_encrypted_data_cipher_data_object(
    expected_encrypted_data_cipher_data_element,
):
    return CipherData.model_validate_etree(expected_encrypted_data_cipher_data_element)


@pytest.fixture
def expected_encrypted_key_encryption_method_element():
    xpath_query = (
        f"//S12:Envelope/S12:Header/wsse:Security/enc:EncryptedKey" f"[@Id='{ENCRYPTED_KEY_ID}']/enc:EncryptionMethod"
    )
    return test_soap_envelope_element.xpath(xpath_query, namespaces=DEFAULT_NAMESPACE_MAP)[0]


@pytest.fixture
def expected_encrypted_key_encryption_method_object(
    expected_encrypted_key_encryption_method_element,
):
    return EncryptionMethod.model_validate_etree(expected_encrypted_key_encryption_method_element)


@pytest.fixture
def expected_encrypted_data_encryption_method_element():
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/wsse:Security/enc:EncryptedData/enc:EncryptionMethod",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]


@pytest.fixture
def expected_encrypted_data_encryption_method_object(
    expected_encrypted_data_encryption_method_element,
):
    return EncryptionMethod.model_validate_etree(expected_encrypted_data_encryption_method_element)


@pytest.fixture
def expected_security_key_info_element():
    xpath_query = f"//S12:Envelope/S12:Header/wsse:Security/enc:EncryptedKey" f"[@Id='{ENCRYPTED_KEY_ID}']/ds:KeyInfo"
    return test_soap_envelope_element.xpath(xpath_query, namespaces=DEFAULT_NAMESPACE_MAP)[0]


@pytest.fixture
def expected_security_key_info_object(expected_security_key_info_element):
    return KeyInfo.model_validate_etree(expected_security_key_info_element)


@pytest.fixture
def expected_signature_key_info_element():
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/wsse:Security/ds:Signature/ds:KeyInfo", namespaces=DEFAULT_NAMESPACE_MAP
    )[0]


@pytest.fixture
def expected_signature_key_info_object(expected_signature_key_info_element):
    return KeyInfo.model_validate_etree(expected_signature_key_info_element)


@pytest.fixture
def expected_signature_element():
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/wsse:Security/ds:Signature", namespaces=DEFAULT_NAMESPACE_MAP
    )[0]


@pytest.fixture
def expected_signature_object(expected_signature_element):
    return Signature.model_validate_etree(expected_signature_element)


@pytest.fixture
def example_signing_binary_security_token_object():
    encoding_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-" "message-security-1.0#Base64Binary"
    value_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-" "x509-token-profile-1.0#X509v3"
    return BinarySecurityToken(
        encoding_type=encoding_type,
        value_type=value_type,
        bst_id=SIGNATURE_BINARY_SECURITY_TOKEN_ID,
        value=receiver_certificate_b64,  # Fixed: use signature cert
    )


@pytest.fixture
def example_encryption_binary_security_token_object():
    encoding_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-" "message-security-1.0#Base64Binary"
    value_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-" "x509-token-profile-1.0#X509v3"
    return BinarySecurityToken(
        encoding_type=encoding_type,
        value_type=value_type,
        bst_id=ENCRYPTION_BINARY_SECURITY_TOKEN_ID,
        value=sender_certificate_b64,  # Fixed: use encryption cert
    )


@pytest.fixture
def expected_message_info_element():
    """XML element for expected message info"""
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/eb:Messaging/eb:UserMessage/eb:MessageInfo",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]


@pytest.fixture
def expected_message_info_object(expected_message_info_element):
    """Expected message info object from XML"""
    return MessageInfo.model_validate_etree(expected_message_info_element)


@pytest.fixture
def example_message_info_object():
    """Example message info object"""
    return MessageInfo(
        timestamp=Timestamp(value=datetime.fromisoformat(MESSAGE_TIMESTAMP)),
        message_id=MessageId(value=MESSAGE_ID),
    )


@pytest.fixture
def expected_party_info_element():
    """XML element for expected party info"""
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/eb:Messaging/eb:UserMessage/eb:PartyInfo",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]


@pytest.fixture
def expected_party_info_object(expected_party_info_element):
    """Expected party info object from XML"""
    return PartyInfo.model_validate_etree(expected_party_info_element)


@pytest.fixture
def example_party_info_object():
    """Example party info object"""
    return PartyInfo(
        party_from=PartyFrom(
            party_id=PartyId(value="9932:9999999999", type_value="urn:fdc:peppol.eu:2017:identifiers:ap"),
            role=Role(value="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator"),
        ),
        party_to=PartyTo(
            party_id=PartyId(value="9932:1111111111", type_value="urn:fdc:peppol.eu:2017:identifiers:ap"),
            role=Role(value="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder"),
        ),
    )


@pytest.fixture
def expected_collaboration_info_element():
    """XML element for expected collaboration info"""
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/eb:Messaging/eb:UserMessage/eb:CollaborationInfo",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]


@pytest.fixture
def expected_collaboration_info_object(expected_collaboration_info_element):
    """Expected collaboration info object from XML"""
    return CollaborationInfo.model_validate_etree(expected_collaboration_info_element)


@pytest.fixture
def example_collaboration_info_object():
    """Example collaboration info object"""
    return CollaborationInfo(
        agreement_ref=AgreementRef(value="urn:fdc:peppol.eu:2017:agreements:tia:ap_provider"),
        service=Service(type_value="cenbii-procid-ubl", value="urn:fdc:peppol.eu:2017:poacc:billing:01:1.0"),
        action=Action(
            value=(
                "busdox-docid-qns::urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice"
                "##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1"
            )
        ),
        conversation_id=ConversationId(value=CONVERSATION_ID),
    )


@pytest.fixture
def expected_message_properties_element():
    """XML element for expected message properties"""
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/eb:Messaging/eb:UserMessage/eb:MessageProperties",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]


@pytest.fixture
def expected_message_properties_object(expected_message_properties_element):
    """Expected message properties object from XML"""
    return MessageProperties.model_validate_etree(expected_message_properties_element)


@pytest.fixture
def example_message_properties_object():
    """Example message properties object"""
    return MessageProperties(
        properties=[
            Property(
                property_type="iso6523-actorid-upis",
                name="originalSender",
                value="9999999999",
            ),
            Property(
                property_type="iso6523-actorid-upis",
                name="finalRecipient",
                value="1111111111",
            ),
        ],
    )


@pytest.fixture
def expected_payload_info_element():
    """XML element for expected payload info"""
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/eb:Messaging/eb:UserMessage/eb:PayloadInfo",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]


@pytest.fixture
def expected_payload_info_object(expected_payload_info_element):
    """Expected payload info object from XML"""
    return PayloadInfo.model_validate_etree(expected_payload_info_element)


@pytest.fixture
def example_payload_info_object():
    """Example payload info object"""
    return PayloadInfo(
        part_info=[
            PartInfo(
                href=ATTACHMENT_PART_URI,
                part_properties=PartProperties(
                    properties=[
                        Property(value="application/xml", name="MimeType"),
                        Property(value="application/gzip", name="CompressionType"),
                    ]
                ),
            )
        ]
    )


@pytest.fixture
def expected_user_message_element():
    """XML element for expected user message"""
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/eb:Messaging/eb:UserMessage",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]


@pytest.fixture
def expected_user_message_object(expected_user_message_element):
    """Expected user message object from XML"""
    return UserMessage.model_validate_etree(expected_user_message_element)


@pytest.fixture
def example_user_message_object(
    example_message_info_object,
    example_party_info_object,
    example_collaboration_info_object,
    example_message_properties_object,
    example_payload_info_object,
):
    """Example user message object"""
    return UserMessage(
        message_info=example_message_info_object,
        party_info=example_party_info_object,
        collaboration_info=example_collaboration_info_object,
        message_properties=example_message_properties_object,
        payload_info=example_payload_info_object,
    )


@pytest.fixture
def expected_messaging_element():
    """XML element for expected messaging"""
    return test_soap_envelope_element.xpath(
        "//S12:Envelope/S12:Header/eb:Messaging",
        namespaces=DEFAULT_NAMESPACE_MAP,
    )[0]


@pytest.fixture
def expected_messaging_object(expected_messaging_element):
    """Expected messaging object from XML"""
    return Messaging.model_validate_etree(expected_messaging_element)


@pytest.fixture
def example_messaging_object(example_user_message_object):
    """Example messaging object"""
    return Messaging(
        messaging_id=MESSAGING_ID,
        w3_org_2003_05_soap_envelope_must_understand=True,
        user_messages=[example_user_message_object],
    )
