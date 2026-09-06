from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from as4.core.trust import UntrustedSignerError, certificate_chain
from as4.models.ebms.user_message import PartyFrom, PartyId, Role

NOW = datetime.now(UTC)
PARTY_FROM = PartyFrom(party_id=PartyId(value="0208:1111111111"), role=Role(value="sender"))


def issue(
    subject,
    issuer=None,
    not_before=NOW - timedelta(days=1),
    not_after=NOW + timedelta(days=365),
    ca=False,
    key_cert_sign=None,
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer_name, issuer_key = (name, key) if issuer is None else issuer
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if key_cert_sign is not None:
        builder = builder.add_extension(key_usage(key_cert_sign), critical=True)
    return builder.sign(issuer_key, hashes.SHA256()), (name, key)


def key_usage(key_cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


@pytest.fixture(scope="module")
def authority():
    return issue("test root", ca=True)


@pytest.fixture(scope="module")
def intermediate(authority):
    _root, root_signer = authority
    return issue("test intermediate", issuer=root_signer, ca=True)


def test_leaf_issued_by_the_anchor_is_trusted(authority):
    root, root_signer = authority
    leaf, _ = issue("leaf", issuer=root_signer)

    assert certificate_chain(root)(PARTY_FROM, leaf) is leaf


def test_leaf_reaches_the_anchor_through_an_intermediate(authority, intermediate):
    root, _ = authority
    intermediate_certificate, intermediate_signer = intermediate
    leaf, _ = issue("leaf", issuer=intermediate_signer)

    assert certificate_chain(root, intermediates=[intermediate_certificate])(PARTY_FROM, leaf) is leaf


def test_missing_intermediate_breaks_the_chain(authority, intermediate):
    root, _ = authority
    _intermediate_certificate, intermediate_signer = intermediate
    leaf, _ = issue("leaf", issuer=intermediate_signer)

    with pytest.raises(UntrustedSignerError, match="does not chain"):
        certificate_chain(root)(PARTY_FROM, leaf)


def test_unrelated_anchor_is_refused(authority):
    _root, root_signer = authority
    leaf, _ = issue("leaf", issuer=root_signer)
    other_root, _ = issue("other root", ca=True)

    with pytest.raises(UntrustedSignerError, match="does not chain"):
        certificate_chain(other_root)(PARTY_FROM, leaf)


def test_expired_leaf_is_refused(authority):
    root, root_signer = authority
    leaf, _ = issue("leaf", issuer=root_signer, not_before=NOW - timedelta(days=2), not_after=NOW - timedelta(days=1))

    with pytest.raises(UntrustedSignerError, match="validity period"):
        certificate_chain(root)(PARTY_FROM, leaf)


def test_revoked_leaf_is_refused(authority):
    root, root_signer = authority
    leaf, _ = issue("leaf", issuer=root_signer)

    with pytest.raises(UntrustedSignerError, match="revoked"):
        certificate_chain(root, revoked=lambda certificate: certificate is leaf)(PARTY_FROM, leaf)


def test_absent_certificate_is_refused(authority):
    root, _ = authority

    with pytest.raises(UntrustedSignerError, match="no certificate"):
        certificate_chain(root)(PARTY_FROM, None)


def test_certificate_chain_requires_an_anchor():
    with pytest.raises(ValueError):
        certificate_chain()


def test_chain_longer_than_the_maximum_depth_is_refused(authority, intermediate):
    root, root_signer = authority
    intermediate_certificate, intermediate_signer = intermediate
    leaf, _ = issue("leaf", issuer=intermediate_signer)

    resolve = certificate_chain(root, intermediates=[intermediate_certificate], maximum_depth=2)
    with pytest.raises(UntrustedSignerError, match="maximum chain depth"):
        resolve(PARTY_FROM, leaf)


def test_anchor_without_the_ca_basic_constraint_is_refused():
    """A self-signed leaf configured as an anchor cannot issue anything, so nothing chains to it."""
    fake_authority, fake_signer = issue("not a ca")
    leaf, _ = issue("leaf", issuer=fake_signer)

    with pytest.raises(UntrustedSignerError, match="does not chain"):
        certificate_chain(fake_authority)(PARTY_FROM, leaf)


def test_intermediate_without_key_cert_sign_is_refused(authority):
    """keyUsage without keyCertSign forbids issuing certificates even when cA is set."""
    root, root_signer = authority
    intermediate_certificate, intermediate_signer = issue(
        "no key cert sign", issuer=root_signer, ca=True, key_cert_sign=False
    )
    leaf, _ = issue("leaf", issuer=intermediate_signer)

    with pytest.raises(UntrustedSignerError, match="does not chain"):
        certificate_chain(root, intermediates=[intermediate_certificate])(PARTY_FROM, leaf)
