from typing import Callable

from cryptography import x509
from as4.core.common import AS4InternalParty
from as4.const import MAXIMUM_DECOMPRESSED_SIZE
from as4.errors import SignerNotConfiguredError
from as4.models.ebms.user_message import PartyFrom
from pydantic import BaseModel, ConfigDict, Field

SignerResolver = Callable[[PartyFrom, x509.Certificate | None], x509.Certificate]
ParticipantAcceptor = Callable[[str], None]


def signer_resolver_not_configured(party_from: PartyFrom, embedded: x509.Certificate | None) -> x509.Certificate:
    raise SignerNotConfiguredError(
        "SecurityPolicy.signer_resolver is unset, so no certificate can be trusted to have signed this message"
    )


class SecurityPolicy(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    # The PMode[].Security parameters consulted while parsing a message.
    sign_required: bool = True
    encrypt_required: bool = True
    signer_resolver: SignerResolver = signer_resolver_not_configured
    required_coverage: frozenset[str] = frozenset({"messaging", "body", "payloads"})
    verify_digests: bool = True
    maximum_decompressed_size: int = MAXIMUM_DECOMPRESSED_SIZE
    # Peppol-level security parameters.
    verify_participants: bool = True


class AS4ParseContext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Only the credentials are used in this flow. The whole party is carried so the local party
    # identity can be logged.
    local_party: AS4InternalParty
    accept_participant: ParticipantAcceptor | None = None

    security_policy: SecurityPolicy = Field(default_factory=SecurityPolicy)
