import xml.sax

# XML data with a potentially malicious external entity
xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "/etc/passwd">
]>
<root>&xxe;</root>
"""

class SecureHandler(xml.sax.ContentHandler):
    def startElement(self, name, attrs):
        pass

    def endElement(self, name):
        pass

    def characters(self, content):
        pass

try:
    # Create a secure parser by explicitly disabling external entity expansion
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, False)
    
    handler = SecureHandler()
    parser.setContentHandler(handler)
    parser.parseString(xml_data)
except xml.sax.SAXParseException as e:
    print(f'Error parsing XML: {e}')

