"""The SBDH pair is encrypted and the MessageProperties pair is not. CEF eDelivery AS4 4.2.6 maps them
row for row -- value against text(), @type against @Authority -- and says the consumer SHOULD check."""

import pytest
from as4 import const
from as4.core.context import SecurityPolicy
from as4.core.exchange import (
    AS4ReceivingExchange,
    ExchangeState,
)
from as4.core.trust import pinned_certificates
from as4.models.unece import sbdh
from as4.profiles.peppol.exceptions import PeppolSBDHException
from as4.profiles.peppol.message import PeppolAS4Message
from as4.profiles.peppol.profile import PeppolAS4Profile
from tests.assets.test_credentials import test_sender

SENT_BY = "0208:2222222222"
SENT_TO = "0208:3333333333"


@pytest.fixture
def parsed(local_party, remote_party, receiving_party, send, receive):
    headers, body = send(local_party, remote_party)
    exchange = receive(headers, body, receiving_party)
    assert exchange.state is ExchangeState.RECEIVED, exchange.error
    return exchange.message


def identifier(value, authority=const.ISO6523_ACTOR_ID):
    return sbdh.Identifier(value=value, authority=authority)


def refusal(parsed, sender, recipient):
    with pytest.raises(PeppolSBDHException) as raised:
        PeppolAS4Message.verify_participants_agree(parsed.message_properties, sender, recipient)
    return raised.value.detail


def test_a_message_whose_halves_agree_is_accepted(parsed):
    properties = parsed.message_properties

    assert (properties.original_sender.value, properties.original_sender.property_type) == (
        SENT_BY,
        const.ISO6523_ACTOR_ID,
    )
    assert (properties.final_recipient.value, properties.final_recipient.property_type) == (
        SENT_TO,
        const.ISO6523_ACTOR_ID,
    )

    PeppolAS4Message.verify_participants_agree(parsed.message_properties, identifier(SENT_BY), identifier(SENT_TO))


def test_an_sbdh_sender_contradicting_the_original_sender_property_is_refused(parsed):
    assert "originalSender" in refusal(parsed, identifier("0208:9999999999"), identifier(SENT_TO))


def test_an_sbdh_receiver_contradicting_the_final_recipient_property_is_refused(parsed):
    assert "finalRecipient" in refusal(parsed, identifier(SENT_BY), identifier("0208:9999999999"))


def test_an_sbdh_authority_contradicting_the_property_type_is_refused(parsed):
    """The mapping has four rows, not two: @type must agree with @Authority even when the values do."""
    detail = refusal(parsed, identifier(SENT_BY, authority="unregistered"), identifier(SENT_TO))

    assert "unregistered" in detail
    assert const.ISO6523_ACTOR_ID in detail


def test_an_sbdh_identifier_with_no_authority_is_refused(parsed):
    """The model no longer invents a scheme the sender never declared, so this is a genuine mismatch."""
    assert "None" in refusal(parsed, identifier(SENT_BY, authority=None), identifier(SENT_TO))


def test_a_message_with_no_message_properties_at_all_is_refused(parsed):
    parsed.soap_envelope.header.messaging.user_message.message_properties = None

    assert "is absent" in refusal(parsed, identifier(SENT_BY), identifier(SENT_TO))


@pytest.fixture
def sbdh_naming(monkeypatch):
    """Make the builder write different participants into the SBDH, then sign as usual.

    Nothing is altered after signing, so the message is correctly signed and correctly encrypted and
    only its two halves disagree. `build_peppol_message` cannot produce one: it writes a single value
    into both.
    """

    def apply(sender, recipient):
        original = PeppolAS4Message.get_standard_business_document.__func__

        def replacement(cls, builder_args, references):
            document = original(cls, builder_args, references)
            header = document.standard_business_document_header
            header.sender = sbdh.Sender(identifier=identifier(sender))
            header.receiver = sbdh.Receiver(identifier=identifier(recipient))
            return document

        monkeypatch.setattr(PeppolAS4Message, "get_standard_business_document", classmethod(replacement))

    return apply


def contradicting(local_party, remote_party, send, sbdh_naming):
    sbdh_naming("0208:9999999999", "0208:3333333333")
    return send(local_party, remote_party)


def test_a_signed_message_whose_halves_disagree_is_refused(
    local_party, remote_party, receiving_party, send, receive, sbdh_naming
):
    headers, body = contradicting(local_party, remote_party, send, sbdh_naming)

    receiving = receive(headers, body, receiving_party)

    assert receiving.state is ExchangeState.REJECTED
    assert "originalSender" in receiving.error.error_detail.value


def test_the_routing_hook_is_never_asked_about_a_contradicted_participant(
    local_party, remote_party, receiving_party, send, sbdh_naming
):
    headers, body = contradicting(local_party, remote_party, send, sbdh_naming)
    asked = []

    receiving = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=receiving_party)
    receiving.receive(
        request_headers=headers,
        request_body=body,
        accept_participant=asked.append,
        security_policy=SecurityPolicy(signer_resolver=pinned_certificates(test_sender.certificate)),
    )

    assert receiving.state is ExchangeState.REJECTED
    assert asked == []


def test_the_check_can_be_switched_off(local_party, remote_party, receiving_party, send, sbdh_naming):
    """CEF eDelivery AS4 4.2.6 makes this a SHOULD, so refusing has to be a policy, not a law."""
    headers, body = contradicting(local_party, remote_party, send, sbdh_naming)

    receiving = AS4ReceivingExchange(profile=PeppolAS4Profile, local_party=receiving_party)
    receiving.receive(
        request_headers=headers,
        request_body=body,
        security_policy=SecurityPolicy(
            verify_participants=False, signer_resolver=pinned_certificates(test_sender.certificate)
        ),
    )

    assert receiving.successful, receiving.error
    assert receiving.message.sender == "0208:9999999999"
