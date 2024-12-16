import xml.etree.ElementTree as ET

# Example of vulnerable XML parsing
def parse_xml(xml_data):
    try:
        # Parse the XML data
        tree = ET.fromstring(xml_data)
        return tree
    except ET.ParseError as e:
        print(f"Parse error: {e}")

# Example XML input that could lead to an XXE attack
xml_input = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&file;</data>
</root>
"""

# Call the function with the vulnerable XML input
result = parse_xml(xml_input)