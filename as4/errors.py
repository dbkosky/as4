from abc import ABC
from pydantic_core import ErrorDetails, ValidationError


class MismatchedLocalPartyError(ValueError):
    def __init__(self, stored_party_id: str, supplied_party_id: str):
        super().__init__(
            f"Exchange was stored under {stored_party_id!r}, not under the supplied {supplied_party_id!r}"
        )


class UnknownProfileError(LookupError):
    def __init__(self, profile_name: str):
        super().__init__(f"No AS4 profile is registered under {profile_name!r}; is its module imported?")


class UnknownReceiptableError(LookupError):
    def __init__(self, error_name: str):
        super().__init__(f"No receiptable error is named {error_name!r}; was it renamed or removed?")


class RepeatedElement(ValueError):
    """Raised by a Singular validator when the schema permits one element and several are present."""


class UntrustedSignerError(Exception):
    """Raised by a SignerResolver that refuses the certificate a message offers."""


class ParticipantNotServicedError(Exception):
    """Raised by a ParticipantAcceptor that refuses to deliver to the addressed participant."""


class RemotePartyNotVerifiedError(Exception):
    """Raised when the access point that sent a message is read before its signature has been verified."""


class ReceiptVerificationError(Exception):
    """Raised when an inbound receipt cannot be trusted as proof of delivery."""


class SignerNotConfiguredError(Exception):
    """A local misconfiguration, not a fault of the remote party, so it escapes rather than producing a receipt."""


class BaseAS4ReceiptableError(ABC, Exception):
    error_code: str
    short_description: str
    description: str
    severity: str
    category: str
    detail: str = ""

    def __init__(self, detail: str = "", **kwargs):
        self.detail = detail or self.detail
        super().__init__(self.detail, **kwargs)

    @classmethod
    def from_stored(cls, detail: str) -> "BaseAS4ReceiptableError":
        error = cls.__new__(cls)
        Exception.__init__(error, detail)
        error.detail = detail
        return error

    @classmethod
    def from_pydantic_error(cls, error_details: ErrorDetails):
        location = "/".join(str(item) for item in error_details["loc"])
        match error_details["type"]:
            case "missing":
                return cls(f"Missing expected content at: {location}")
            case _:
                return cls(f"{error_details['msg']} at: {location}")

    @classmethod
    def from_validation_error(cls, exception: ValidationError) -> "BaseAS4ReceiptableError":
        error_details, *_ = exception.errors()
        if isinstance(error_details.get("ctx", {}).get("error"), RepeatedElement):
            location = "/".join(str(item) for item in error_details["loc"])
            return DuplicateHeaderElementException(detail=f"Repeated element at: {location}")
        return BaseValueInconsistentException.from_pydantic_error(error_details)


class BaseFeatureNotSupportedException(BaseAS4ReceiptableError):
    error_code = "EBMS:0002"
    short_description = "FeatureNotSupported"
    description = (
        "Although the message document is well formed and schema valid, some element/attribute value "
        "cannot be processed as expected because the related feature is not supported by the MSH."
    )
    severity = "warning"
    category = "Content"


class BundledMessagesNotSupportedException(BaseFeatureNotSupportedException):
    detail = "eb:Messaging bundles more than one message"


class BaseValueInconsistentException(BaseAS4ReceiptableError):
    error_code = "EBMS:0003"
    short_description = "ValueInconsistent"
    description = (
        "Although the message document is well formed and schema valid, some element/attribute value is inconsistent "
        "either with the content of other element/attribute, or with the processing mode of the MSH, or with the "
        "normative requirements of the ebMS specification."
    )
    severity = "failure"
    category = "Content"


class UserMessageNotFoundException(BaseValueInconsistentException):
    detail = "Missing UserMessage in ebMS Messaging header"


class PayloadInfoNotFoundException(BaseValueInconsistentException):
    detail = "Missing PayloadInfo in UserMessage"


class MessagingNotFoundException(BaseValueInconsistentException):
    """Raised when Messaging header is missing from the SOAP envelope."""


class MessageIdNotFoundException(BaseValueInconsistentException):
    """Raised when MessageId or MessagingId cannot be extracted from the message."""


class PartyToNotFoundException(BaseValueInconsistentException):
    """Raised when the PartyInfo/To element cannot be found in the message."""


class BaseProfileLevelException(BaseAS4ReceiptableError):
    error_code = "EBMS:0004"
    short_description = "Other"
    severity = "failure"
    category = "Content"


class BaseMimeInconsistencyException(BaseAS4ReceiptableError):
    error_code = "EBMS:0007"
    short_description = "MimeInconsistency"
    description = "The use of MIME is not consistent with the required usage in this specification."
    severity = "failure"
    category = "Unpackaging"


class PartInfoWithoutMimePartException(BaseMimeInconsistencyException):
    def __init__(self, href: str, **kwargs):
        detail = f"eb:PartInfo/@href {href} names no MIME part in the message"
        super().__init__(detail, **kwargs)


class BaseInvalidHeaderException(BaseAS4ReceiptableError):
    error_code = "EBMS:0009"
    short_description = "InvalidHeader"
    description = (
        "The ebMS header is either not valid against the ebMS packaging rules, or not conform to the "
        "processing mode of the MSH."
    )
    severity = "failure"
    category = "Unpackaging"


class DuplicateHeaderElementException(BaseInvalidHeaderException):
    detail = "A header element permitted once appears more than once"


class MalformedSoapEnvelopeException(BaseInvalidHeaderException):
    detail = "SOAP part is not well-formed XML"


class SoapPartNotFoundException(BaseInvalidHeaderException):
    detail = "Message carries no readable application/soap+xml part"


class PayloadPartNotFoundException(BaseInvalidHeaderException):
    detail = "Message carries no readable application/octet-stream part"


class BaseDecompressionFailureException(BaseAS4ReceiptableError):
    error_code = "EBMS:0303"
    short_description = "DecompressionFailure"
    description = "An error occurred during the decompression."
    severity = "failure"
    category = "Communication"


class DecompressionFailedException(BaseDecompressionFailureException):
    detail = "Payload is not valid gzip"


class DecompressedPayloadTooLargeException(BaseDecompressionFailureException):
    detail = "Decompressed payload exceeds the configured maximum size"


class BaseFailedAuthenticationException(BaseAS4ReceiptableError):
    error_code = "EBMS:0101"
    short_description = "FailedAuthentication"
    description = (
        "The signature in the Security header intended for the "
        '"ebms" SOAP actor, could not be validated by the Security '
        "module."
    )
    severity = "failure"
    category = "Processing"


class DigestMismatchException(BaseFailedAuthenticationException):
    def __init__(self, uri: str, **kwargs):
        detail = f"Digest mismatch for signature reference {uri}"
        super().__init__(detail, **kwargs)


class ReferenceTargetNotFoundException(BaseFailedAuthenticationException):
    def __init__(self, uri: str, **kwargs):
        detail = f"Cannot resolve signature reference {uri}"
        super().__init__(detail, **kwargs)


class DuplicateElementIdException(BaseFailedAuthenticationException):
    """Two elements sharing one id is how signature wrapping hides the unsigned copy."""

    def __init__(self, identifier: str, **kwargs):
        detail = f"Duplicate element id {identifier}"
        super().__init__(detail, **kwargs)


class SignatureSecurityTokenReferenceNotFoundException(BaseFailedAuthenticationException):
    detail = "Missing or empty SecurityTokenReference URI for Signature"


class SignatureCoverageException(BaseFailedAuthenticationException):
    """AS4 5.1.4 and 5.1.5 require the eb:Messaging block, the SOAP Body and every payload part."""

    def __init__(self, missing: list[str], **kwargs):
        detail = f"Signature does not cover {', '.join(missing)}"
        super().__init__(detail, **kwargs)


class UntrustedSignerException(BaseFailedAuthenticationException):
    detail = "Signing certificate rejected"


class SignatureVerificationFailedException(BaseFailedAuthenticationException):
    detail = "Signature does not verify against the signing certificate"


class BaseEncryptedDataReferenceException(BaseAS4ReceiptableError):
    error_code = "EBMS:0102"
    short_description = "FailedDecryption"
    description = (
        "The encrypted data reference the Security header intended "
        'for the "ebms" SOAP actor could not be decrypted by the '
        "Security Module."
    )
    severity = "failure"
    category = "Processing"


class EncryptedDataReferenceNotFoundException(BaseEncryptedDataReferenceException):
    detail = "Error processing the WSSecurity Header, cannot find a reference to the encrypted data"


class EncryptedDataNotFoundException(BaseEncryptedDataReferenceException):
    def __init__(self, encrypted_data_uri: str, **kwargs):
        detail = (
            "Error processing the WSSecurity Header, cannot find the EncryptedData with the reference "
            f"{encrypted_data_uri}."
        )
        super().__init__(detail, **kwargs)


class CipherValueNotFoundException(BaseEncryptedDataReferenceException):
    detail = "Error processing the WSSecurity Header, missing xenc:CipherData / xenc:CipherValue from EncryptedKey"


class CipherReferenceNotFoundException(BaseEncryptedDataReferenceException):
    detail = (
        "Error processing the WSSecurity Header, missing xenc:CipherData / xenc:CipherReference from EncryptedData"
    )


class EncryptedAttachmentNotFoundException(BaseEncryptedDataReferenceException):
    def __init__(self, attachment_id: str, **kwargs):
        detail = f"Error processing the WSSecurity Header, no MIME attachment matches cid:{attachment_id}"
        super().__init__(detail, **kwargs)


class DecryptionFailedException(BaseEncryptedDataReferenceException):
    """One detail for every decryption failure: distinguishable causes are a padding oracle."""

    detail = "Could not decrypt the message payload"


class BasePolicyNoncomplianceException(BaseAS4ReceiptableError):
    error_code = "EBMS:0103"
    short_description = "PolicyNoncompliance"
    description = (
        "The processor determined that the message's security methods, parameters, scope or other "
        "security policy-level requirements or agreements were not satisfied."
    )
    severity = "failure"
    category = "Processing"


class SignatureRequiredException(BasePolicyNoncomplianceException):
    detail = "SecurityPolicy requires a signature and the message carries no ds:Signature"


class EncryptionRequiredException(BasePolicyNoncomplianceException):
    detail = "SecurityPolicy requires encryption and the message carries no xenc:EncryptedKey"


class UnsupportedSecurityTokenTypeException(BasePolicyNoncomplianceException):
    def __init__(self, value_type: str, **kwargs):
        detail = f"Unsupported security token value type {value_type}"
        super().__init__(detail, **kwargs)


class UnsupportedSignatureAlgorithmException(BasePolicyNoncomplianceException):
    def __init__(self, algorithm: str, **kwargs):
        detail = f"Unsupported signature algorithm {algorithm}"
        super().__init__(detail, **kwargs)


class UnsupportedEncryptionAlgorithmException(BasePolicyNoncomplianceException):
    def __init__(self, algorithm: str, **kwargs):
        detail = f"Unsupported encryption algorithm {algorithm}"
        super().__init__(detail, **kwargs)


class UnsupportedTransformException(BasePolicyNoncomplianceException):
    def __init__(self, algorithm: str, **kwargs):
        detail = f"Unsupported transform {algorithm}"
        super().__init__(detail, **kwargs)


class UnsupportedDigestAlgorithmException(BasePolicyNoncomplianceException):
    def __init__(self, algorithm: str, **kwargs):
        detail = f"Unsupported digest algorithm {algorithm}"
        super().__init__(detail, **kwargs)
