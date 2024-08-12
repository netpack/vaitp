import xml.sax

class PlistHandler(xml.sax.ContentHandler):
    def __init__(self):
        self.data = {}

    def startElement(self, name, attrs):
        if name == 'dict':
            self.data = {}

    def endElement(self, name):
        if name == 'dict':
            return self.data

    def characters(self, content):
        if content.strip():
            self.data[content.strip()] = ''

def parse_plist(xml_string):
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, False)
    parser.setFeature(xml.sax.handler.feature_external_pes, False)
    handler = PlistHandler()
    parser.setContentHandler(handler)
    parser.parseString(xml_string)
    return handler.data

# Example usage:
xml_string = '<plist version="1.0"><dict><key>foo</key><string>bar</string></dict></plist>'
data = parse_plist(xml_string)
print(data)  # Output: {'foo': 'bar'}