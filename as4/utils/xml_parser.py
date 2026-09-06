from lxml import etree


def hardened_parser() -> etree.XMLParser:
    return etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False)


def parse_xml(data: bytes) -> etree._Element:
    return etree.fromstring(data, parser=hardened_parser())


def id_attributes(element: etree._Element) -> list[tuple[str, etree._Element]]:
    return [
        (str(value), descendant)
        for descendant in element.iter()
        for key, value in descendant.attrib.items()
        if etree.QName(key).localname == "Id"
    ]
