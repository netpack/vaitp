# This code is for demonstration purposes only. Do not use it in production.
import xml.etree.ElementTree as ET

# This XML file contains an external entity reference to a malicious DTD
xml_file = "malicious.xml"

# This will trigger the vulnerability and cause the parser to hang
tree = ET.parse(xml_file)
root = tree.getroot()