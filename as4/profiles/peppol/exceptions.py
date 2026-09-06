from as4.const import PEPPOL_PARTY_IDENTIFIER_TYPE
from as4.errors import BaseProfileLevelException


class PeppolSBDHException(BaseProfileLevelException):
    description = "Undefined SBDH error"


class PeppolPartyIdentifierException(BaseProfileLevelException):
    description = "Party identifier does not follow the Peppol AS4 profile"

    def __init__(self, element: str, scheme: str | None):
        detail = f"PartyInfo/{element}/PartyId/@type must be {PEPPOL_PARTY_IDENTIFIER_TYPE}, not {scheme!r}"
        super().__init__(detail)


class PeppolNotServicedException(BaseProfileLevelException):
    """Peppol AS4 2.0.3 requires EBMS:0004 with this exact errorDetail when the addressee is not serviced."""

    description = "The addressed participant is not serviced by this access point"
    detail = "PEPPOL:NOT_SERVICED"
