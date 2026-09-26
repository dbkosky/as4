import pytest
from as4 import const
from as4.core.pmode import MEP, PMode, PModeLeg, PModeLegSecurity, PModeParty
from as4.profiles.peppol.pmode import peppol_pmode
from pydantic import ValidationError

SECURITY = PModeLegSecurity(
    signature_algorithm=const.DSIG_RSA_SHA256,
    signature_digest_algorithm=const.XMLENC_SHA256,
    encryption_algorithm=const.AES_128_GCM,
)
INITIATOR = PModeParty(party_id="A", role=const.INITIATOR)
RESPONDER = PModeParty(party_id="B", role=const.RESPONDER)


def test_one_way_by_default():
    pmode = PMode(id="p", initiator=INITIATOR, responder=RESPONDER, leg1=PModeLeg(security=SECURITY))
    assert pmode.mep is MEP.ONE_WAY
    assert pmode.leg2 is None


def test_a_one_way_pmode_refuses_a_second_leg():
    leg = PModeLeg(security=SECURITY)
    with pytest.raises(ValidationError, match="single leg"):
        PMode(id="p", initiator=INITIATOR, responder=RESPONDER, leg1=leg, leg2=leg)


def test_a_two_way_pmode_needs_a_second_leg():
    with pytest.raises(ValidationError, match="second leg"):
        PMode(id="p", mep=MEP.TWO_WAY, initiator=INITIATOR, responder=RESPONDER, leg1=PModeLeg(security=SECURITY))


def test_pmode_is_frozen():
    pmode = PMode(id="p", initiator=INITIATOR, responder=RESPONDER, leg1=PModeLeg(security=SECURITY))
    with pytest.raises(ValidationError):
        pmode.id = "q"


def test_security_has_no_algorithm_defaults():
    with pytest.raises(ValidationError):
        PModeLegSecurity()  # type: ignore[call-arg]


def test_party_identity_round_trips():
    party = PModeParty(party_id="POP000123", party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE, role=const.INITIATOR)
    assert party.identity.party_id == "POP000123"
    assert party.identity.party_type == const.PEPPOL_PARTY_IDENTIFIER_TYPE


def test_peppol_pmode_fixes_everything_but_the_parties_and_address():
    pmode = peppol_pmode("POP000123", "POP000456", "https://ap.example/as4")
    assert pmode.id == "POP000123-POP000456"
    assert pmode.agreement == const.PEPPOL_AP_PROVIDER
    assert pmode.initiator.party_type == const.PEPPOL_PARTY_IDENTIFIER_TYPE
    assert pmode.leg1.protocol.address == "https://ap.example/as4"
    assert pmode.leg1.business_info.service is None
    assert pmode.leg1.business_info.service_type == const.CENBII_PROCID_UBL
    assert pmode.leg1.security.encryption_algorithm == const.AES_128_GCM


def test_peppol_pmode_is_deterministic():
    assert peppol_pmode("A", "B", "u") == peppol_pmode("A", "B", "u")
