import xml.etree.ElementTree as ET

def safe_parse(xml_string):
    parser = ET.XMLParser(resolve_entities=False)
    return ET.fromstring(xml_string, parser=parser)

# Example usage
xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
"""

# This will raise an error or not include the external entity
try:
    result = safe_parse(xml_data)
    print(ET.tostring(result).decode())
except ET.ParseError as e:
    print("Error parsing XML:", e)