"""lxml keeps validation errors on the schema object, so two requests must not read each other's."""

import threading

from lxml import etree
from as4.resources.schemas.vendor.sbdh import SBDHSchema

NS = "http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader"
MISSING_SENDER = f'<StandardBusinessDocumentHeader xmlns="{NS}"><HeaderVersion>1.0</HeaderVersion></{{}}>'
MISSING_VERSION = f'<StandardBusinessDocumentHeader xmlns="{NS}"><Sender><Identifier>x</Identifier></Sender></{{}}>'


def test_concurrent_validations_do_not_report_each_others_errors():
    mistaken: list[str | None] = []
    guard = threading.Lock()

    def validate_repeatedly(document: str, expected: str) -> None:
        element = etree.fromstring(document.format("StandardBusinessDocumentHeader").encode())
        for _ in range(300):
            reported = SBDHSchema.validation_error(element)
            if reported is None or expected not in reported:
                with guard:
                    mistaken.append(reported)

    threads = [
        threading.Thread(target=validate_repeatedly, args=(MISSING_SENDER, "Sender")),
        threading.Thread(target=validate_repeatedly, args=(MISSING_VERSION, "HeaderVersion")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert mistaken == []
