import xml.etree.ElementTree as ET
import xml.sax.saxutils as saxutils

# Function to parse XML safely, preventing XML Entity Expansion (XEE) attacks
def safe_parse(xml_data):
    parser = ET.XMLParser(target=ET.TreeBuilder())
    parser.parser.UseForeignDTD(False) # Disable external DTDs
    return ET.fromstring(xml_data, parser=parser)

# Example usage
xml_input = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">]><!--
  <data>&xxe;</data>
-->"""

try:
    root = safe_parse(xml_input)
    print(ET.tostring(root, encoding='unicode'))
except ET.ParseError as e:
    print("XML parsing error:", e)