import pytest
from as4.core.context import SecurityPolicy
from as4.core.message import AS4Message
from as4.core.trust import pinned_certificates
from as4.errors import SignerNotConfiguredError, UntrustedSignerError
from as4.profiles.peppol.profile import certificate_names_the_sender
from as4.models.ebms.user_message import PartyFrom, PartyId, Role

from tests.test_components.test_certificate_chain import issue

AP_IDENTIFIER = "POP000123"
PARTY = PartyFrom(party_id=PartyId(value=AP_IDENTIFIER), role=Role(value="sender"))


@pytest.fixture(scope="module")
def access_point():
    return issue(AP_IDENTIFIER)[0]


def test_an_unconfigured_resolver_refuses_every_message(access_point):
    """The default fails closed, so a policy that forgets its resolver cannot accept a signature."""
    with pytest.raises(SignerNotConfiguredError):
        AS4Message.resolve_signer(SecurityPolicy(), PARTY, access_point)


def test_a_configured_resolver_returns_the_certificate_it_trusts(access_point):
    policy = SecurityPolicy(signer_resolver=pinned_certificates(access_point))
    assert AS4Message.resolve_signer(policy, PARTY, access_point) is access_point


def test_a_certificate_issued_to_another_access_point_cannot_sign_as_this_one(access_point):
    """Peppol AS4 4.5 puts the AP identifier in the Subject CN, so a valid certificate is not a free identity."""
    impostor = issue("POP000456")[0]
    resolve = certificate_names_the_sender(pinned_certificates(access_point, impostor))

    with pytest.raises(UntrustedSignerError, match=AP_IDENTIFIER):
        resolve(PARTY, impostor)

    assert resolve(PARTY, access_point) is access_point
