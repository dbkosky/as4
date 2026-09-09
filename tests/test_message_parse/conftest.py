import pytest
from as4 import const
from as4.core.common import (
    AS4BaseCredentials,
    AS4ExternalParty,
    AS4InternalCredentials,
    AS4InternalParty,
    AS4PartyIdentity,
)
from as4.core.context import SecurityPolicy
from as4.core.exchange import (
    AS4ReceivingExchange,
    AS4SendingExchange,
)
from as4.core.references import AS4References
from as4.core.trust import pinned_certificates
from as4.profiles.peppol.message import PeppolAS4MessageBuilderArgs
from as4.profiles.peppol.document_identifier import BusdoxDocidQnsDocumentIdentifier
from as4.profiles.peppol.profile import PeppolAS4Profile, parse_peppol_receipt
from tests.assets.test_credentials import test_receiver, test_sender
from as4.core.common import AS4LocalPrivateKey

SENDING_AP_ID = "PTE000001"
RECEIVING_AP_ID = "PTE000002"
PAYLOAD = b'<Invoice xmlns="urn:test">payload</Invoice>'
DOCUMENT_TYPE_IDENTIFIER = (
    "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice"
    "##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1"
)


@pytest.fixture
def local_party():
    return AS4InternalParty(
        identity=AS4PartyIdentity(party_id=SENDING_AP_ID, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
        credentials=AS4InternalCredentials(
            certificate=test_sender.certificate, private_key=AS4LocalPrivateKey(test_sender.private_key)
        ),
    )


@pytest.fixture
def remote_party():
    return AS4ExternalParty(
        identity=AS4PartyIdentity(party_id=RECEIVING_AP_ID, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
        credentials=AS4BaseCredentials(certificate=test_receiver.certificate),
    )


@pytest.fixture
def receiving_party():
    return AS4InternalParty(
        identity=AS4PartyIdentity(party_id=RECEIVING_AP_ID, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
        credentials=AS4InternalCredentials(
            certificate=test_receiver.certificate, private_key=AS4LocalPrivateKey(test_receiver.private_key)
        ),
    )


@pytest.fixture
def build_args():
    def make(local_party, remote_party):
        return PeppolAS4MessageBuilderArgs(
            local_party=local_party,
            remote_party=remote_party,
            sender="9932:2222222222",
            recipient="9932:3333333333",
            document_type_identifier=BusdoxDocidQnsDocumentIdentifier.from_identifier_value(DOCUMENT_TYPE_IDENTIFIER),
            document_identification_instance_identifier="instance",
            process_identifier="urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
            c1_country_id="BE",
        )

    return make


@pytest.fixture
def send(build_args):
    def make(local_party, remote_party, references=None):
        sending = AS4SendingExchange(
            profile=PeppolAS4Profile,
            local_party=local_party,
            remote_party=remote_party,
            identifiers=references or AS4References(),
        )
        return sending.build(PAYLOAD, build_args(local_party, remote_party))

    return make


@pytest.fixture
def receive():
    def make(headers, body, receiving_party):
        exchange = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=receiving_party)
        exchange.receive(
            request_headers=headers,
            request_body=body,
            security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
        )
        return exchange

    return make


@pytest.fixture
def read_signal():
    def make(receiving):
        """Round-trip the signal so a test proves a peer could read it, not just that bytes are present."""
        _headers, payload = receiving.build_signal()
        return payload, parse_peppol_receipt(payload, test_receiver.certificate)

    return make
