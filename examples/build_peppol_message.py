import requests
from as4 import SecurityPolicy, pinned_certificates
from as4.peppol import (
    build_peppol_message,
    create_peppol_external_party,
    create_peppol_internal_party,
    parse_peppol_message,
    parse_peppol_receipt,
)
from examples import example_receiver, example_sender

# --- SENDER FLOW ----
local_party = create_peppol_internal_party(
    party_id="PTE000001",
    certificate=example_sender.certificate,
    private_key=example_sender.private_key,
)
remote_party = create_peppol_external_party(
    party_id="PTE000002",
    certificate=example_receiver.certificate,
)

message = build_peppol_message(
    payload=b'<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"/>',
    local_party=local_party,
    remote_party=remote_party,
    sender="9932:9999999999",
    recipient="9932:1111111111",
    sender_country_id="GB",
    document_type_identifier_scheme="busdox-docid-qns",
    document_type_identifier_value=(
        "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::"
        "Invoice##"
        "urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:01:1.0::"
        "2.1"
    ),
    process_identifier="urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
)

# Get MIME parts for HTTP transmission
data, boundary = message.get_request_data()
http_headers = message.get_http_headers(boundary)

# At this point the request could be sent
# e.g. requests.post("http://localhost:8080/as4", data=data, headers=http_headers)

# in this scenario we'll create the request but won't send it
req = requests.Request(
    "POST",
    "http://localhost:8080/as4",
    data=data,
    headers=http_headers,
)
prepared = req.prepare()


# --- RECEIVER FLOW ---
receiving = parse_peppol_message(
    request_headers=prepared.headers,
    request_body=prepared.body,
    local_party=create_peppol_internal_party(
        party_id="PTE000002",
        certificate=example_receiver.certificate,
        private_key=example_receiver.private_key,
    ),
    security_policy=SecurityPolicy(signer_resolver=pinned_certificates(example_sender.certificate)),
)
headers, payload = receiving.build_signal()
# At this point the receiving access point would return a response like that below
# Response(
#     response=payload,
#     headers=headers,
# )


# --- SENDER FLOW  (PARSE RECEIPT) ----
receipt = parse_peppol_receipt(payload, example_receiver.certificate)
receipt.verify_non_repudiation(message.signed_references)
