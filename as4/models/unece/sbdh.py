from datetime import datetime

from as4.models.common import BaseElement, Singular, WildcardSpecification
from pydantic import Field


class HeaderVersion(BaseElement):
    value: str = Field(alias="#text")


class Identifier(BaseElement):
    authority: str | None = Field(alias="@Authority", default=None)
    value: str = Field(alias="#text")


class Sender(BaseElement):
    identifier: Singular[Identifier] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}Identifier"
    )


class Receiver(BaseElement):
    identifier: Singular[Identifier] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}Identifier"
    )


class Standard(BaseElement):
    value: str = Field(alias="#text")


class TypeVersion(BaseElement):
    value: str = Field(alias="#text")


class InstanceIdentifier(BaseElement):
    value: str = Field(alias="#text")


class SBDHType(BaseElement):
    value: str = Field(alias="#text")


class CreationDateAndTime(BaseElement):
    value: datetime = Field(alias="#text")


class DocumentIdentification(BaseElement):
    standard: Singular[Standard] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}Standard"
    )

    type_version: Singular[TypeVersion] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}TypeVersion"
    )
    instance_identifier: Singular[InstanceIdentifier] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}InstanceIdentifier"
    )
    document_identification_type: Singular[SBDHType] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}Type"
    )
    creation_date_and_time: Singular[CreationDateAndTime] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}CreationDateAndTime"
    )


class ScopeIdentifier(BaseElement):
    value: str = Field(alias="#text")


class Scope(BaseElement):
    scope_type: Singular[SBDHType] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}Type"
    )
    instance_identifier: Singular[InstanceIdentifier] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}InstanceIdentifier"
    )
    identifier: Singular[ScopeIdentifier] | None = Field(
        default=None,
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}Identifier",
    )


class BusinessScope(BaseElement):
    scopes: list[Scope] = Field(alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}Scope")


class StandardBusinessDocumentHeader(BaseElement):
    header_version: Singular[HeaderVersion] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}HeaderVersion"
    )

    sender: Singular[Sender] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}Sender"
    )
    receiver: Singular[Receiver] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}Receiver"
    )
    document_identification: Singular[DocumentIdentification] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}DocumentIdentification"
    )
    business_scope: Singular[BusinessScope] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}BusinessScope"
    )


class StandardBusinessDocument(BaseElement):
    standard_business_document_header: Singular[StandardBusinessDocumentHeader] = Field(
        alias="{http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader}StandardBusinessDocumentHeader"
    )

    @classmethod
    def wildcard_specification(cls) -> WildcardSpecification:
        return WildcardSpecification(namespace="##any")
