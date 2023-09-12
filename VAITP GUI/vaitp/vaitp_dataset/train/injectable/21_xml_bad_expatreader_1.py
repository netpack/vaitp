import xml.sax

# XML data with a potentially malicious external entity
xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "/etc/passwd">
]>
<root>&xxe;</root>
"""

class SecureHandler(xml.sax.handler.ContentHandler):
    def __init__(self):
        super().__init__()

    def startElement(self, name, attrs):
        pass

    def endElement(self, name):
        pass

    def characters(self, content):
        pass

try:
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, False)  # Disable external entity expansion
    handler = SecureHandler()
    parser.setContentHandler(handler)
    parser.feed(xml_data)
except xml.sax.SAXParseException as e:
    print(f'Error parsing XML: {e}')
