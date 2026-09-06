# as4

A Python library for building, parsing and answering AS4 messages, with the Peppol AS4 profile as its first profile.

[![Python package](https://github.com/dbkosky/as4/actions/workflows/python-package.yml/badge.svg)](https://github.com/dbkosky/as4/actions/workflows/python-package.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

## Features

- One-Way/Push user messages: build, sign (RSA-SHA256, exc-c14n), gzip and encrypt (AES-128-GCM under RSA-OAEP) payloads as MIME attachments.
- Receive side: verify the signature against a configurable trust policy, check coverage of `eb:Messaging`, the SOAP Body and every payload, decrypt, decompress within a size cap, and answer with a signed non-repudiation receipt or an ebMS error signal.
- Sending side: verify the receipt that comes back, correlate it to the message and check the acknowledged digests against what was signed.
- Peppol profile: SBDH envelope, `originalSender`/`finalRecipient` message properties, Peppol PKI trust anchors, `PEPPOL:NOT_SERVICED` feedback.
- `AS4SendingExchange`/`AS4ReceivingExchange` model the lifecycle of one message and serialise to JSON, without their private key, so a receipt can be verified after a restart.

Not implemented: One-Way/Pull, Two-Way MEPs, duplicate detection, retries and MissingReceipt reporting. These belong to the calling application or to a later release.

## Installation

```bash
pip install as4
```

Or from source:

```bash
git clone https://github.com/dbkosky/as4.git
cd as4
pip install -e ".[test]"
```

## Supported surface

`as4` and `as4.peppol` are the public API. Everything under `as4.core`, `as4.models` and `as4.utils`
is internal and may move without notice.

## Quick start

`examples/build_peppol_message.py` runs the whole round trip with the bundled test credentials.

### Building a Peppol AS4 message

```python
from as4.peppol import build_peppol_message, create_peppol_external_party, create_peppol_internal_party

local_party = create_peppol_internal_party(party_id="PTE000001", certificate=my_certificate, private_key=my_key)
remote_party = create_peppol_external_party(party_id="PTE000002", certificate=their_certificate)

message = build_peppol_message(
    payload=invoice_xml_bytes,
    local_party=local_party,
    remote_party=remote_party,
    sender="0208:9999999999",
    recipient="0208:1111111111",
    sender_country_id="GB",
    document_type_identifier_scheme="busdox-docid-qns",
    document_type_identifier_value="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##...::2.1",
    process_identifier="urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
)
body, boundary = message.get_request_data()
headers = message.get_http_headers(boundary)
# POST body with headers to the remote access point
```

### Parsing a Peppol AS4 message

```python
from as4.peppol import PEPPOL_PROD_SECURITY_POLICY, parse_peppol_message

receiving = parse_peppol_message(
    request_headers=request.headers,
    request_body=request.body,
    local_party=local_party,
    security_policy=PEPPOL_PROD_SECURITY_POLICY,
)
headers, signal = receiving.build_signal()
# respond with signal and headers, whether or not receiving.successful
if receiving.successful:
    payload = next(iter(receiving.message.decrypted_data.values()))
```

`PEPPOL_TEST_SECURITY_POLICY` trusts the Peppol test PKI. `as4.pinned_certificates` and `as4.certificate_chain` build a `SecurityPolicy` for other trust arrangements.

### Verifying the receipt

```python
from as4.peppol import parse_peppol_receipt

receipt = parse_peppol_receipt(response_body, remote_party.credentials.certificate)
receipt.verify_non_repudiation(message.signed_references)
```

## Running tests

```bash
./run_tests.sh
```

This runs black, mypy, flake8 and pytest, the same gate as CI.

## Specifications

- [ebMS 3.0 Core](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/os/ebms_core-3.0-spec-os.pdf)
- [AS4 Profile of ebMS 3.0 v1.0](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/os/AS4-profile-v1.0-os.html)
- [CEF eDelivery AS4 1.14](https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/eDelivery+AS4+-+1.14)
- [Peppol AS4 Profile 2.0.3](https://docs.peppol.eu/edelivery/as4/specification/)
- [Peppol Business Message Envelope 2.0.1](https://docs.peppol.eu/edelivery/envelope/Peppol-EDN-Business-Message-Envelope-2.0.1-2023-08-17.pdf)

## Licence

Apache 2.0, see `LICENSE.txt`.
