from importlib import resources

from lxml import etree

resource = resources.files("tests.assets.test_message")
test_soap_envelope_file = resource / "test_soap_envelope.xml"
test_soap_envelope_raw = test_soap_envelope_file.open("rb").read()
test_soap_envelope_element = etree.fromstring(test_soap_envelope_raw)

test_as4_mime_file = resource / "test_as4.mime"
test_as4_mime = test_as4_mime_file.open("rb").read()
