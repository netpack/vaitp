import xml.etree.ElementTree as ET

def parse_xml(xml_data):
    # Secure parsing by disabling external entity processing
    parser = ET.XMLParser(resolve_entities=False)
    tree = ET.fromstring(xml_data, parser=parser)
    return tree

# Example XML input (still could be malicious)
xml_input = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>"""

try:
    result = parse_xml(xml_input)
    print(ET.tostring(result, encoding='unicode'))
except Exception as e:
    print(f"An error occurred: {e}")