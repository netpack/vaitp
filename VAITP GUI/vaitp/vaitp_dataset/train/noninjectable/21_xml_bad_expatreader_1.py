import xml.sax.expatreader as expatreader

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
    handler = MyHandler()
    parser = expatreader.create_parser()
    parser.setContentHandler(handler)
    parser.parseString(xml_data)
except xml.sax.SAXParseException as e:
    print(f'Error parsing XML: {e}')
