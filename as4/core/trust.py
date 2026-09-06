from datetime import UTC, datetime
from typing import Callable, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from as4.core.context import SignerResolver
from as4.errors import UntrustedSignerError
from as4.models.ebms.user_message import PartyFrom

FINGERPRINT_ALGORITHM = hashes.SHA256()
MAXIMUM_CHAIN_DEPTH = 8


def pinned_certificates(*certificates: x509.Certificate) -> SignerResolver:
    if not certificates:
        raise ValueError("pinned_certificates requires at least one certificate")
    configured = {certificate.fingerprint(FINGERPRINT_ALGORITHM): certificate for certificate in certificates}

    def resolve(party_from: PartyFrom, embedded: x509.Certificate | None) -> x509.Certificate:
        if embedded is None:
            raise UntrustedSignerError("no certificate accompanied the signature")
        fingerprint = embedded.fingerprint(FINGERPRINT_ALGORITHM)
        if fingerprint not in configured:
            raise UntrustedSignerError(
                f"{embedded.subject.rfc4514_string()} is not pinned for {party_from.party_id.value}"
            )
        return configured[fingerprint]

    return resolve


def can_issue_certificates(certificate: x509.Certificate) -> bool:
    try:
        if not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return False
    except x509.ExtensionNotFound:
        return False
    try:
        return certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
    except x509.ExtensionNotFound:
        return True


def issuer_of(
    certificate: x509.Certificate,
    candidates: Sequence[x509.Certificate],
) -> x509.Certificate | None:
    for candidate in candidates:
        if not can_issue_certificates(candidate):
            continue
        try:
            certificate.verify_directly_issued_by(candidate)
        except (ValueError, TypeError, InvalidSignature):
            continue
        return candidate
    return None


def path_to_anchor(
    leaf: x509.Certificate,
    anchors: Sequence[x509.Certificate],
    intermediates: Sequence[x509.Certificate],
    maximum_depth: int = MAXIMUM_CHAIN_DEPTH,
) -> list[x509.Certificate]:
    path = [leaf]
    while len(path) < maximum_depth:
        anchor = issuer_of(path[-1], anchors)
        if anchor is not None:
            return path + [anchor]
        intermediate = issuer_of(path[-1], [candidate for candidate in intermediates if candidate not in path])
        if intermediate is None:
            raise UntrustedSignerError(f"{leaf.subject.rfc4514_string()} does not chain to a configured anchor")
        path.append(intermediate)
    raise UntrustedSignerError(f"{leaf.subject.rfc4514_string()} exceeds the maximum chain depth")


def certificate_chain(
    *anchors: x509.Certificate,
    intermediates: Sequence[x509.Certificate] = (),
    revoked: Callable[[x509.Certificate], bool] | None = None,
    maximum_depth: int = MAXIMUM_CHAIN_DEPTH,
) -> SignerResolver:
    if not anchors:
        raise ValueError("certificate_chain requires at least one trust anchor")

    def resolve(party_from: PartyFrom, embedded: x509.Certificate | None) -> x509.Certificate:
        if embedded is None:
            raise UntrustedSignerError("no certificate accompanied the signature")
        path = path_to_anchor(embedded, anchors, intermediates, maximum_depth)
        now = datetime.now(UTC)
        for certificate in path:
            if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
                raise UntrustedSignerError(f"{certificate.subject.rfc4514_string()} is outside its validity period")
            if revoked is not None and revoked(certificate):
                raise UntrustedSignerError(f"{certificate.subject.rfc4514_string()} is revoked")
        return embedded

    return resolve
