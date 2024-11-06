from encoder import XML2Dict 
import xml.etree.ElementTree as ET

class SecureXML2Dict(XML2Dict):
    def parse(self, xml_string):
        # Disable DTDs to prevent XXE attacks
        parser = ET.XMLParser(resolve_entities=False)
        return ET.fromstring(xml_string, parser=parser)

xml2dic = SecureXML2Dict() 
doc = """ <!--?xml version="1.0" ?--> <bombz>Safe content</bombz> """ 
xml2dic.parse(doc) 