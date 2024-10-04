# This code is for demonstration purposes only. Do not use it in production.
import xml.etree.ElementTree as ET

# This XML file contains an external entity reference to a malicious DTD
xml_file = "malicious.xml"

# This will create a secure parser that ignores external entities
parser = ET.XMLParser(resolve_entities=False)
tree = ET.parse(xml_file, parser=parser)
root = tree.getroot()