import xml.sax

class PlistHandler(xml.sax.ContentHandler):
    def __init__(self):
        self.data = {}
        self.current_key = None
        self.in_dict = False
        self.current_dict = None

    def startElement(self, name, attrs):
        if name == 'dict':
            if self.in_dict:
              self.current_dict = {}
            else:
              self.current_dict = self.data
              self.in_dict = True
        elif name == 'key':
            self.current_key = ''
        elif name == 'string':
            self.current_value = ''


    def endElement(self, name):
      if name == 'dict' and self.in_dict:
            if isinstance(self.current_dict, dict) and isinstance(self.data,dict) :
                if not self.current_key is None:
                   self.data[self.current_key]= self.current_dict
                else:
                    self.data = self.current_dict
            self.in_dict = False
      elif name == 'key':
        pass #no action
      elif name == 'string':
         if self.current_key:
          self.current_dict[self.current_key] = self.current_value
          self.current_key = None

    def characters(self, content):
        if self.current_key is not None:
             self.current_key += content
        elif hasattr(self, 'current_value'):
             self.current_value += content


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
print(data)