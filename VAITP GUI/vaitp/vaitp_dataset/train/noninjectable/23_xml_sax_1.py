import xml.sax

# XML data with a potentially malicious external entity
xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "/etc/passwd">
]>
<root>&xxe;</root>
"""

class MyHandler(xml.sax.ContentHandler):
    def startElement(self, name, attrs):
        pass

    def endElement(self, name):
        pass

    def characters(self, content):
        pass

try:
    # Parse the XML data using the default SAX parser
    parser = xml.sax.make_parser()
    handler = MyHandler()
    parser.setContentHandler(handler)
    parser.parseString(xml_data)
except xml.sax.SAXParseException as e:
    print(f'Error parsing XML: {e}')
