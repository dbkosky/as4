from as4.models.common import BaseElement, Singular
from as4.models.ebms.messaging import Messaging
from as4.models.wsse.security import Security
from pydantic import Field


class Header(BaseElement):
    security: Singular[Security] = Field(
        alias="{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security"
    )
    messaging: Singular[Messaging] = Field(
        alias="{http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/}Messaging"
    )
