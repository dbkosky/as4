"""Peppol envelope 2.0.1 names the identifier scheme in each scope, and the receiver reads the schemes back."""

from lxml import etree
from as4.core.exchange import ExchangeState

NAMESPACES = {"sh": "http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader"}


def scopes_of(payload):
    document = etree.fromstring(payload)
    return {
        scope.findtext("sh:Type", namespaces=NAMESPACES): (
            scope.findtext("sh:InstanceIdentifier", namespaces=NAMESPACES),
            scope.findtext("sh:Identifier", namespaces=NAMESPACES),
        )
        for scope in document.iterfind(".//sh:Scope", namespaces=NAMESPACES)
    }


def test_the_envelope_names_the_scheme_of_each_identifier_and_the_receiver_reads_them(
    local_party, remote_party, receiving_party, send, receive, build_args
):
    args = build_args(local_party, remote_party)
    receiving = receive(*send(local_party, remote_party), receiving_party)
    assert receiving.state is ExchangeState.RECEIVED, receiving.error
    (payload,) = receiving.message.decrypted_data.values()

    assert scopes_of(payload)["DOCUMENTID"] == (args.document_type_identifier.identifier_value, "busdox-docid-qns")
    assert scopes_of(payload)["PROCESSID"] == (args.process_identifier, "cenbii-procid-ubl")
    assert receiving.message.document_type_identifier_value == args.document_type_identifier.identifier_value
    assert receiving.message.document_type_identifier_scheme == "busdox-docid-qns"
    assert receiving.message.process_identifier == args.process_identifier
