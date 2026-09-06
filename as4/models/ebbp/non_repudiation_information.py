from as4.models.common import BaseElement
from as4.models.dsig.reference import Reference
from pydantic import Field


class MessagePartNRInformation(BaseElement):
    references: list[Reference] = Field(alias="{http://www.w3.org/2000/09/xmldsig#}Reference")


class NonRepudiationInformation(BaseElement):
    message_part_nr_information: list[MessagePartNRInformation] = Field(
        default_factory=list, alias="{http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0}MessagePartNRInformation"
    )
