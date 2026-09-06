import threading
from importlib import resources
from typing import Any, cast

from lxml import etree

resource = resources.files("as4.resources.schemas.vendor.sbdh")

with resources.as_file(resource) as schema_dir:
    sbdh_schema_path = schema_dir / "StandardBusinessDocumentHeader.xsd"
    sbdh_schema_element = etree.parse(sbdh_schema_path)
    sbdh_schema = etree.XMLSchema(sbdh_schema_element)


class SBDHSchema:
    lock = threading.Lock()

    @classmethod
    def validation_error(cls, element: etree._Element) -> str | None:
        with cls.lock:
            if sbdh_schema.validate(element):
                return None
            last_error = cast(Any, sbdh_schema.error_log).last_error
            return last_error.message if last_error is not None else ""
