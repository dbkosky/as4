from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import Policy
from importlib.metadata import PackageNotFoundError, version
from typing import cast
from uuid import uuid4

from as4.errors import PayloadPartNotFoundException, SoapPartNotFoundException
from urllib3.fields import RequestField
from urllib3.filepost import choose_boundary, encode_multipart_formdata

PROJECT_URL = "https://github.com/dbkosky/as4"


class MIMEHandler:

    parser = BytesParser(policy=cast(Policy, policy.default))

    @classmethod
    def self_user_agent(cls) -> str:
        try:
            return f"as4/{version('as4')} (+{PROJECT_URL})"
        except PackageNotFoundError:
            return f"as4 (+{PROJECT_URL})"

    @classmethod
    def payload_from_request(
        cls,
        request_headers: dict,
        request_body: bytes,
    ) -> bytes:
        mime_headers = [
            f"{header_name}: {header_value}".encode("utf-8") for header_name, header_value in request_headers.items()
        ]
        return b"\r\n".join([*mime_headers, b"", request_body])

    @classmethod
    def parse(cls, message: bytes) -> tuple[EmailMessage, EmailMessage]:
        parsed_message = cast(EmailMessage, cls.parser.parsebytes(message))
        soap_part = cls.get_soap_part(parsed_message)
        if soap_part is None:
            raise SoapPartNotFoundException()
        encrypted_part = cls.get_encrypted_part(parsed_message)
        if encrypted_part is None:
            raise PayloadPartNotFoundException()
        return soap_part, encrypted_part

    @classmethod
    def get_soap_part(cls, message: EmailMessage) -> EmailMessage | None:
        match message.get_content_type():
            case "multipart/related":
                for part in map(cls.get_soap_part, [cast(EmailMessage, part) for part in message.iter_parts()]):
                    if part is None:
                        continue
                    return part
            case "application/soap+xml":
                return message
        return None

    @classmethod
    def get_encrypted_part(cls, message: EmailMessage) -> EmailMessage | None:
        match message.get_content_type():
            case "multipart/related":
                for part in map(cls.get_encrypted_part, [cast(EmailMessage, part) for part in message.iter_parts()]):
                    if part is None:
                        continue
                    return part
            case "application/octet-stream":
                return message
        return None

    @classmethod
    def get_content_id(cls, part: EmailMessage) -> str | None:
        content_id = part.get("content-id")
        if content_id is None:
            return None
        return str(content_id).strip().strip("<>")

    @classmethod
    def make_soap_part_request_field(cls, soap_envelope_bytes: bytes) -> RequestField:
        return RequestField(
            name="soap_field",
            data=soap_envelope_bytes,
            headers={"Content-Type": "application/soap+xml; charset=UTF-8"},
        )

    @classmethod
    def make_attachment_part_request_field(cls, part_cid: str, attachment_bytes: bytes) -> RequestField:
        return RequestField(
            name="attachment",
            data=attachment_bytes,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-ID": f"<{part_cid}>",
            },
        )

    @classmethod
    def build_request_data(
        cls,
        soap_envelope_bytes: bytes,
        attachments: list[tuple[str, bytes]] | None = None,
        boundary: str | None = None,
    ) -> tuple[bytes, str]:

        if boundary is None:
            boundary = choose_boundary()

        if attachments is None:
            attachments = []

        soap_part_request_field = cls.make_soap_part_request_field(soap_envelope_bytes=soap_envelope_bytes)
        attachment_request_fields = [
            cls.make_attachment_part_request_field(attachment_cid, attachment_bytes)
            for attachment_cid, attachment_bytes in attachments
        ]
        body, _ingore_content_type = encode_multipart_formdata(
            [soap_part_request_field, *attachment_request_fields], boundary
        )
        return body, boundary

    @classmethod
    def build_request_headers(
        cls,
        boundary: str,
        message_id: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, str]:

        if message_id is None:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            message_id = f"<{timestamp}-{uuid4()}-@as4>"

        return {
            "Content-Type": f'multipart/related; type="application/soap+xml"; boundary="{boundary}"',
            "Message-ID": message_id,
            "Mime-Version": "1.0",
            "User-Agent": user_agent or cls.self_user_agent(),
        }
