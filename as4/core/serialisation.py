import base64
from typing import Annotated, Any, Iterator, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from as4.errors import BaseAS4ReceiptableError, UnknownReceiptableError
from pydantic import BeforeValidator, PlainSerializer

Descendant = TypeVar("Descendant")


def descendants(cls: type[Descendant]) -> Iterator[type[Descendant]]:
    for subclass in cls.__subclasses__():
        yield subclass
        yield from descendants(subclass)


def load_certificate(value: Any) -> Any:
    if isinstance(value, str):
        return x509.load_der_x509_certificate(base64.b64decode(value))
    return value


def dump_certificate(certificate: x509.Certificate) -> str:
    return base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode("ascii")


SerialisableCertificate = Annotated[
    x509.Certificate,
    BeforeValidator(load_certificate),
    PlainSerializer(dump_certificate, return_type=str, when_used="json"),
]


def load_bytes(value: Any) -> Any:
    if isinstance(value, str):
        return base64.b64decode(value)
    return value


def dump_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


SerialisableBytes = Annotated[
    bytes,
    BeforeValidator(load_bytes),
    PlainSerializer(dump_bytes, return_type=str, when_used="json"),
]


def load_parse_error(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    errors_by_name = {error.__name__: error for error in descendants(BaseAS4ReceiptableError)}
    error_class = errors_by_name.get(value["type"])
    if error_class is None:
        raise UnknownReceiptableError(value["type"])
    return error_class.from_stored(value["detail"])


def dump_parse_error(error: BaseAS4ReceiptableError) -> dict[str, str]:
    return {"type": type(error).__name__, "detail": error.detail}


SerialisableParseError = Annotated[
    BaseAS4ReceiptableError,
    BeforeValidator(load_parse_error),
    PlainSerializer(dump_parse_error, return_type=dict[str, str], when_used="json"),
]
