import re

from pydantic import BaseModel


class BusdoxDocidQnsDocumentIdentifier(BaseModel):
    scheme: str = "busdox-docid-qns"
    syntax_specific_id: str
    customization_id: str
    version: str

    @classmethod
    def from_identifier_value(cls, document_type_identifier: str) -> "BusdoxDocidQnsDocumentIdentifier":
        qns_match_string = r"(?P<syntax_specific_id>.*)##(?P<customization_id>.*)::(?P<version>.*)"
        matches = re.match(qns_match_string, document_type_identifier)
        if matches:
            syntax_specific_id, customization_id, version = matches.groups()
            if all([syntax_specific_id, customization_id, version]):
                return cls(
                    syntax_specific_id=matches["syntax_specific_id"],
                    customization_id=matches["customization_id"],
                    version=matches["version"],
                )

        raise ValueError("Cannot construct BusdoxDocidQnsDocumentIdentifier from document_type_identifier")

    @property
    def root_element_namespace(self) -> str:
        return self.syntax_specific_id.split("::")[0]

    @property
    def root_element_name(self) -> str:
        return self.syntax_specific_id.split("::")[1]

    @property
    def identifier_value(self) -> str:
        return f"{self.syntax_specific_id}##{self.customization_id}::{self.version}"

    @property
    def action(self) -> str:
        return f"{self.scheme}::{self.identifier_value}"
