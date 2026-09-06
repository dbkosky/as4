import json
import re

import pytest
from pydantic import ValidationError
from as4 import const
from as4.errors import MismatchedLocalPartyError, ParticipantNotServicedError, UnknownProfileError
from as4.core.common import (
    AS4BaseCredentials,
    AS4ExternalParty,
    AS4InternalCredentials,
    AS4InternalParty,
    AS4PartyIdentity,
)
from as4.core.context import SecurityPolicy
from as4.core.message import AS4Message
from as4.core.receipt import AS4Receipt
from as4.errors import BaseValueInconsistentException, ReceiptVerificationError
from as4.core.exchange import (
    AS4Exchange,
    AS4ReceivingExchange,
    AS4SendingExchange,
    ExchangeState,
)
from as4.core.profiles import AS4Profile
from as4.core.trust import pinned_certificates
from as4.profiles.peppol.profile import PeppolAS4Profile
from as4.profiles.peppol.message import PeppolAS4Message, PeppolAS4MessageBuilderArgs
from as4.profiles.peppol.document_identifier import BusdoxDocidQnsDocumentIdentifier
from tests.assets.test_credentials import test_receiver, test_sender

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
        credentials=AS4InternalCredentials(certificate=test_sender.certificate, private_key=test_sender.private_key),
    )


@pytest.fixture
def remote_party():
    return AS4ExternalParty(
        identity=AS4PartyIdentity(party_id=RECEIVING_AP_ID, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
        credentials=AS4BaseCredentials(certificate=test_receiver.certificate),
    )


@pytest.fixture
def local_receiver():
    return AS4InternalParty(
        identity=AS4PartyIdentity(party_id=RECEIVING_AP_ID, party_type=const.PEPPOL_PARTY_IDENTIFIER_TYPE),
        credentials=AS4InternalCredentials(
            certificate=test_receiver.certificate,
            private_key=test_receiver.private_key,
        ),
    )


def without_party_to(body):
    return re.sub(rb"<eb3:To>.*?</eb3:To>", b"", body, flags=re.DOTALL)


def builder_args():
    return PeppolAS4MessageBuilderArgs(
        sender="0208:2222222222",
        recipient="0208:3333333333",
        document_type_identifier=BusdoxDocidQnsDocumentIdentifier.from_identifier_value(DOCUMENT_TYPE_IDENTIFIER),
        document_identification_instance_identifier="instance-1",
        process_identifier="urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
        c1_country_id="BE",
    )


@pytest.fixture
def exchanged(local_party, remote_party, local_receiver):
    """Drive a full round trip and hand back the sending exchange plus the signal bytes."""
    sending = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    headers, body = sending.build(PAYLOAD, builder_args())
    sending.mark_sent()

    receiving = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=local_receiver)
    receiving.receive(
        request_headers=headers,
        request_body=body,
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )
    _, signal_body = receiving.build_signal()
    return sending, receiving, signal_body


def test_a_round_trip_leaves_both_sides_acknowledged(exchanged):
    sending, receiving, signal_body = exchanged

    sending.receive_signal(signal_body)

    assert sending.state is ExchangeState.ACKNOWLEDGED
    assert sending.successful
    assert receiving.successful


def test_a_signal_for_another_exchange_is_refused(exchanged, local_party, remote_party):
    _sending, _receiving, signal_body = exchanged
    other = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    other.build(b'<Invoice xmlns="urn:test">other</Invoice>', builder_args())
    other.mark_sent()

    with pytest.raises(ReceiptVerificationError, match="not to this exchange"):
        other.receive_signal(signal_body)


def test_the_receiving_exchange_records_the_conversation_id_from_the_wire(exchanged):
    sending, receiving, _signal = exchanged

    assert receiving.conversation_id == sending.conversation_id


def test_the_receiving_exchange_records_the_sender_it_verified(exchanged):
    _sending, receiving, _signal = exchanged

    assert receiving.remote_party.identity.party_id == SENDING_AP_ID
    assert receiving.remote_party.credentials.certificate is not None


def test_a_foreign_signal_leaves_the_exchange_untouched(exchanged, local_party, remote_party):
    _sending, _receiving, signal_body = exchanged
    other = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    other.build(b'<Invoice xmlns="urn:test">other</Invoice>', builder_args())
    other.mark_sent()

    with pytest.raises(ReceiptVerificationError):
        other.receive_signal(signal_body)

    assert other.state is ExchangeState.SENT
    assert other.receipt is None


def test_a_receipt_failing_non_repudiation_marks_the_exchange_failed(exchanged):
    sending, _receiving, signal_body = exchanged
    sending.signed_references = [
        reference.model_copy(update={"digest_value": "0" * 44}) for reference in sending.signed_references
    ]

    with pytest.raises(ReceiptVerificationError):
        sending.receive_signal(signal_body)

    assert sending.state is ExchangeState.FAILED
    assert sending.receipt is not None


class UnknownRecipientException(BaseValueInconsistentException):
    detail = "Recipient is not hosted here"


def test_a_message_with_no_party_to_still_produces_a_signed_error_signal(local_party, remote_party, local_receiver):
    """The receiving side signs with its configured credentials, so a message missing eb3:To can still be answered."""
    sending = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    headers, body = sending.build(PAYLOAD, builder_args())

    receiving = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=local_receiver)
    receiving.receive(
        request_headers=headers,
        request_body=without_party_to(body),
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )

    assert receiving.message.addressed_to is None
    assert receiving.state is ExchangeState.REJECTED
    assert receiving.error is not None
    assert receiving.error.error_code == "EBMS:0003"
    _headers, signal = receiving.build_signal()
    assert b"ds:SignatureValue" in signal


def test_an_error_signal_rejects_the_sending_exchange_without_raising(local_party, remote_party, local_receiver):
    """A peer refusing the message is a protocol outcome, not a verification failure."""
    sending = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    headers, body = sending.build(PAYLOAD, builder_args())
    sending.mark_sent()

    def refuse(_participant_id):
        raise UnknownRecipientException()

    receiving = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=local_receiver)
    receiving.receive(
        request_headers=headers,
        request_body=body,
        accept_participant=refuse,
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )
    _headers, signal = receiving.build_signal()

    sending.receive_signal(signal)

    assert sending.state is ExchangeState.REJECTED
    assert sending.error is not None
    assert sending.error.error_code == "EBMS:0003"


def test_the_parsed_message_records_the_access_point_it_was_addressed_to(local_party, remote_party, local_receiver):
    """eb3:To is a claim by the sender, kept on the message, not where the receiving side gets its identity."""
    sending = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    headers, body = sending.build(PAYLOAD, builder_args())

    receiving = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=local_receiver)
    receiving.receive(
        request_headers=headers,
        request_body=body,
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )

    assert receiving.message.addressed_to is not None
    assert receiving.message.addressed_to.party_id == RECEIVING_AP_ID


def test_a_build_that_fails_part_way_leaves_the_exchange_untouched(local_party, remote_party, monkeypatch):
    """Each verb gathers into locals and assigns once, so a half-built message is never recorded."""
    exchange = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)

    def refuse(self, *args, **kwargs):
        raise RuntimeError("serialisation failed")

    monkeypatch.setattr(PeppolAS4Message, "get_request_data", refuse)

    with pytest.raises(RuntimeError):
        exchange.build(PAYLOAD, builder_args())

    assert exchange.state is ExchangeState.CREATED
    assert exchange.message is None
    assert exchange.message_id == exchange.identifiers.message_id
    assert exchange.signed_references == []


def test_a_receiving_exchange_exists_before_anything_is_received(local_receiver):
    """Constructors set up and verbs move, so there is an exchange to inspect before receive runs."""
    exchange = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=local_receiver)

    assert exchange.state is ExchangeState.CREATED
    assert exchange.local_party is local_receiver
    assert exchange.message is None
    assert exchange.receipt is None


def test_the_shared_base_cannot_be_instantiated(local_party):
    """The base is the role-agnostic view, not an exchange in its own right."""
    with pytest.raises(TypeError, match="abstract"):
        AS4Exchange(profile=PeppolAS4Profile, local_party=local_party)


def test_both_messaging_roles_answer_the_reads_the_base_declares(local_party, remote_party, local_receiver):
    """A caller holding an AS4Exchange can ask any of these without knowing which side it is."""
    sending = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    receiving = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=local_receiver)

    for exchange in (sending, receiving):
        assert exchange.successful is False
        assert exchange.error is None
        assert exchange.errors == []

    assert sending.conversation_id == sending.identifiers.conversation_id
    assert receiving.conversation_id is None


def test_a_sending_exchange_cannot_exist_without_a_remote_party(local_party):
    """The messaging role is the type, so having nobody to build for is a construction error, not a build-time one."""
    with pytest.raises(ValidationError, match="remote_party"):
        AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party)

    assert not hasattr(AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=local_party), "build")


def test_the_envelope_names_access_points_and_the_sbdh_names_participants(local_party, remote_party):
    """AS4 From/To carry seat IDs; the SBDH and the C1/C4 properties carry participant IDs."""
    exchange = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    _headers, body = exchange.build(PAYLOAD, builder_args())

    assert exchange.message is not None
    assert exchange.message.sender == "0208:2222222222"
    assert exchange.message.recipient == "0208:3333333333"

    envelope = body.split(b"--")[1]
    assert SENDING_AP_ID.encode() in envelope
    assert RECEIVING_AP_ID.encode() in envelope
    assert b"0208:2222222222" in envelope
    assert b"0208:3333333333" in envelope


def test_a_participant_refusal_answers_with_the_code_peppol_mandates(local_party, remote_party, local_receiver):
    """Peppol AS4 2.0.3: an unserviced addressee MUST be answered with EBMS:0004 and PEPPOL:NOT_SERVICED."""
    sending = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    headers, body = sending.build(PAYLOAD, builder_args())

    def refuse(_participant_id):
        raise ParticipantNotServicedError("not hosted here")

    receiving = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=local_receiver)
    receiving.receive(
        request_headers=headers,
        request_body=body,
        accept_participant=refuse,
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )

    assert receiving.state is ExchangeState.REJECTED
    assert receiving.error is not None
    assert receiving.error.error_code == "EBMS:0004"
    assert receiving.error.severity == "failure"
    assert receiving.error.error_detail.value == "PEPPOL:NOT_SERVICED"
    _headers, signal = receiving.build_signal()
    assert b"PEPPOL:NOT_SERVICED" in signal
    assert b"ds:SignatureValue" in signal


def test_refusing_an_unhosted_participant_produces_a_signed_error_signal(local_party, remote_party, local_receiver):
    """Refusal happens after decryption, where the participant is legible and the signing key is settled."""
    sending = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    headers, body = sending.build(PAYLOAD, builder_args())
    checked = []

    def refuse(participant_id):
        checked.append(participant_id)
        raise UnknownRecipientException()

    receiving = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=local_receiver)
    receiving.receive(
        request_headers=headers,
        request_body=body,
        accept_participant=refuse,
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )

    assert checked == ["0208:3333333333"]
    assert receiving.state is ExchangeState.REJECTED
    assert receiving.message.signer_certificate is not None
    assert receiving.remote_party is not None, "a rejected parse still knows who signed the message"
    assert receiving.error is not None
    assert receiving.error.error_code == "EBMS:0003"
    _headers, signal = receiving.build_signal()
    assert b"Recipient is not hosted here" in signal
    assert b"ds:SignatureValue" in signal


def test_a_parsed_message_carries_the_participants_from_its_sbdh(local_party, remote_party, local_receiver):
    """The SBDH identifiers survive parsing, so a receiver can route on the participant."""
    sending = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    headers, body = sending.build(PAYLOAD, builder_args())

    receiving = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=local_receiver)
    receiving.receive(
        request_headers=headers,
        request_body=body,
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )

    assert receiving.successful, receiving.error
    assert receiving.message is not None
    assert receiving.message.sender == "0208:2222222222"
    assert receiving.message.recipient == "0208:3333333333"


def test_the_envelope_of_a_built_message_can_be_read_as_xml(local_party, remote_party):
    sending = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    sending.build(PAYLOAD, builder_args())

    assert sending.message.soap_envelope.etree_element is None, "a built envelope has never been parsed"
    assert b"eb3:Messaging" in sending.message.soap_envelope_xml


def test_a_message_with_no_envelope_says_so_wherever_it_is_read():
    with pytest.raises(ValueError, match="Message carries no SOAP envelope"):
        AS4Message().soap_envelope_xml

    with pytest.raises(ValueError, match="Message carries no SOAP envelope"):
        AS4Message().get_request_data()


def test_a_receipt_with_no_envelope_says_so():
    with pytest.raises(ValueError, match="Receipt carries no SOAP envelope"):
        AS4Receipt().get_request_data()


def test_a_signal_names_the_exchange_it_answers_before_its_signer_is_known(exchanged):
    sending, _receiving, signal_body = exchanged

    assert PeppolAS4Profile.correlate_signal(signal_body) == sending.message_id


def test_correlating_something_that_is_not_a_signal_yields_nothing():
    assert PeppolAS4Profile.correlate_signal(b"<not-xml") is None
    assert PeppolAS4Profile.correlate_signal(b"<unrelated/>") is None


def test_a_sending_exchange_survives_a_round_trip(exchanged, local_party):
    sending, _receiving, _signal = exchanged

    resumed = AS4SendingExchange.restore(sending.model_dump_json(), local_party)

    assert resumed.message_id == sending.message_id
    assert resumed.messaging_id == sending.messaging_id
    assert resumed.state is sending.state
    assert resumed.signed_references == sending.signed_references
    assert resumed.remote_party.credentials.certificate == sending.remote_party.credentials.certificate
    assert resumed.message.soap_envelope_xml == sending.message.soap_envelope_xml


def test_a_serialised_exchange_names_its_local_party_but_never_its_private_key(exchanged):
    sending, _receiving, _signal = exchanged

    serialised = json.loads(sending.model_dump_json())

    identity = {"party_id": SENDING_AP_ID, "party_type": const.PEPPOL_PARTY_IDENTIFIER_TYPE}
    assert serialised["local_party"] == {"identity": identity}
    assert "private_key" not in sending.model_dump_json()


def test_an_exchange_restored_under_the_wrong_local_party_is_refused(exchanged, local_receiver):
    sending, _receiving, _signal = exchanged

    with pytest.raises(MismatchedLocalPartyError, match=RECEIVING_AP_ID):
        AS4SendingExchange.restore(sending.model_dump_json(), local_receiver)


def test_a_resumed_receiving_exchange_still_signs_the_signal_it_owes(exchanged, local_receiver):
    _sending, receiving, signal_body = exchanged

    resumed = AS4ReceivingExchange.restore(receiving.model_dump_json(), local_receiver)
    _headers, resumed_signal = resumed.build_signal()

    assert resumed_signal == signal_body


def test_a_resumed_sending_exchange_verifies_the_signal_it_was_waiting_for(exchanged, local_party):
    sending, _receiving, signal_body = exchanged

    resumed = AS4SendingExchange.restore(sending.model_dump_json(), local_party)
    resumed.receive_signal(signal_body)

    assert resumed.state is ExchangeState.ACKNOWLEDGED
    assert resumed.successful


def test_a_refused_message_carries_its_error_across_a_round_trip(local_party, remote_party, local_receiver):
    sending = AS4SendingExchange(profile=PeppolAS4Profile, local_party=local_party, remote_party=remote_party)
    headers, body = sending.build(PAYLOAD, builder_args())
    receiving = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=local_receiver)
    receiving.receive(
        request_headers=headers,
        request_body=without_party_to(body),
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )

    resumed = AS4ReceivingExchange.restore(receiving.model_dump_json(), local_receiver)

    assert resumed.state is ExchangeState.REJECTED
    assert type(resumed.message.parse_error) is type(receiving.message.parse_error)
    assert resumed.error.error_code == "EBMS:0003"
    _headers, signal = resumed.build_signal()
    assert b"ds:SignatureValue" in signal


def test_the_payload_survives_a_round_trip(exchanged, local_receiver):
    _sending, receiving, _signal = exchanged

    resumed = AS4ReceivingExchange.restore(receiving.model_dump_json(), local_receiver)

    assert resumed.message.mime_attachments == receiving.message.mime_attachments
    assert PAYLOAD in b"".join(resumed.message.decrypted_data.values())


def test_an_exchange_stored_under_an_unknown_profile_is_refused(exchanged, local_party):
    sending, _receiving, _signal = exchanged
    serialised = sending.model_dump_json().replace('"peppol"', '"nonesuch"')

    with pytest.raises(UnknownProfileError, match="is its module imported"):
        AS4SendingExchange.restore(serialised, local_party)


def test_a_profile_can_be_found_by_the_name_it_is_stored_under():
    assert AS4Profile.by_name("peppol") is PeppolAS4Profile
