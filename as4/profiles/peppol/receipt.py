from as4.core.receipt import AS4Receipt


class PeppolAS4Receipt(AS4Receipt):
    peppol_message_id: str | None = None
