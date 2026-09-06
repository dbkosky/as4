from lxml import etree
from as4.utils.xml_parser import parse_xml

EXTERNAL_ENTITY = b"""<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY secret SYSTEM "file:///etc/hostname"> ]>
<r>&secret;</r>"""

INTERNAL_ENTITY = b"""<?xml version="1.0"?>
<!DOCTYPE r [
 <!ENTITY a "AAAAAAAAAA">
 <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
 <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<r>&c;</r>"""

PREDEFINED_ENTITIES = b'<?xml version="1.0"?><r><a>x &amp; y &lt;z&gt;</a><b><![CDATA[raw & stuff]]></b></r>'


def test_external_entities_are_not_resolved():
    assert not parse_xml(EXTERNAL_ENTITY).text


def test_internal_entities_are_not_expanded():
    """lxml expands these by default, amplifying a few hundred bytes into tens of kilobytes."""
    assert len(etree.fromstring(INTERNAL_ENTITY).text) == 1000
    assert not parse_xml(INTERNAL_ENTITY).text


def test_predefined_entities_and_cdata_still_work():
    parsed = parse_xml(PREDEFINED_ENTITIES)
    assert parsed[0].text == "x & y <z>"
    assert parsed[1].text == "raw & stuff"
