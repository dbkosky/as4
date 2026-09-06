from uuid import uuid4

from pydantic import BaseModel, Field


def default_message_id() -> str:
    return f"{uuid4()}@as4"


def default_messaging_id() -> str:
    return f"as4-msg-{uuid4()}"


def default_conversation_id() -> str:
    return f"as4@{uuid4()}"


def default_encrypted_key_bst_id() -> str:
    return str(uuid4())


def default_signature_bst_id() -> str:
    return f"X509-{uuid4()}"


def default_encrypted_key_id() -> str:
    return f"EK-{uuid4()}"


def default_encrypted_data_id() -> str:
    return f"ED-{uuid4()}"


def default_signature_id() -> str:
    return f"SIG-{uuid4()}"


def default_key_info_id() -> str:
    return f"KI-{uuid4()}"


def default_signature_security_token_reference_id() -> str:
    return f"STR-{uuid4()}"


def default_body_id() -> str:
    return str(uuid4())


class AS4References(BaseModel):
    message_id: str = Field(default_factory=default_message_id)
    messaging_id: str = Field(default_factory=default_messaging_id)
    conversation_id: str = Field(default_factory=default_conversation_id)
    encrypted_key_bst_id: str = Field(default_factory=default_encrypted_key_bst_id)
    signature_bst_id: str = Field(default_factory=default_signature_bst_id)
    encrypted_key_id: str = Field(default_factory=default_encrypted_key_id)
    signature_id: str = Field(default_factory=default_signature_id)
    key_info_id: str = Field(default_factory=default_key_info_id)
    signature_security_token_reference_id: str = Field(default_factory=default_signature_security_token_reference_id)
    body_id: str = Field(default_factory=default_body_id)
    attachment_id_encrypted_data_id_map: dict[str, str] = Field(default_factory=dict)

    def encrypted_data_attachment_mapping(self) -> tuple[str, str]:
        if not self.attachment_id_encrypted_data_id_map:
            self.attachment_id_encrypted_data_id_map[f"as4-att-{uuid4()}@cid"] = f"ED-{uuid4()}"
        return next(iter(self.attachment_id_encrypted_data_id_map.items()))
