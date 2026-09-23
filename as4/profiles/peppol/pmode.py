from as4 import const
from as4.core.pmode import (
    MEP,
    MEPBinding,
    PMode,
    PModeLeg,
    PModeLegBusinessInfo,
    PModeLegProtocol,
    PModeLegSecurity,
    PModeParty,
)


def peppol_pmode_id(initiator_id: str, responder_id: str) -> str:
    """Derived P-Modes need stable ids, so an exchange can name the one it used and it can be rebuilt."""
    return f"{initiator_id}-{responder_id}"


def peppol_pmode(initiator_id: str, responder_id: str, address: str | None = None) -> PMode:
    """Everything is fixed by the Peppol AS4 profile except who the two access points are and where to send."""
    return PMode(
        id=peppol_pmode_id(initiator_id, responder_id),
        agreement=const.PEPPOL_AP_PROVIDER,
        mep=MEP.ONE_WAY,
        binding=MEPBinding.PUSH,
        initiator=PModeParty(
            party_id=initiator_id, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE, role=const.INITIATOR
        ),
        responder=PModeParty(
            party_id=responder_id, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE, role=const.RESPONDER
        ),
        leg1=PModeLeg(
            protocol=PModeLegProtocol(address=address),
            # The process and document type vary per message, so only the service type is fixed.
            business_info=PModeLegBusinessInfo(service_type=const.CENBII_PROCID_UBL),
            security=PModeLegSecurity(
                signature_algorithm=const.DSIG_RSA_SHA256,
                signature_digest_algorithm=const.XMLENC_SHA256,
                encryption_algorithm=const.AES_128_GCM,
                encryption_minimum_strength=128,
            ),
        ),
    )
