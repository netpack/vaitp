import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    # Secure code that prevents external entities
    parser = ET.XMLParser(resolve_entities=False)
    return ET.fromstring(xml_string, parser)

# Example XML input (same as before)
xml_input = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>"""

# This will raise an error or ignore the external entity
try:
    result = parse_xml(xml_input)
    print(result)
except ET.ParseError as e:
    print("Error parsing XML:", e)