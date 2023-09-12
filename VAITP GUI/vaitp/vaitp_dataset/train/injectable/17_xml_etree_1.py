import xml.etree.ElementTree as ET

# XML data with a potentially malicious external entity
xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "/etc/passwd">
]>
<root>&xxe;</root>
"""

try:
    # Create an XMLParser with no_network=True to disable external entity expansion
    parser = ET.XMLParser(no_network=True)

    # Parse the XML data
    root = ET.fromstring(xml_data, parser=parser)

    # Access and print the root element
    print(root.tag)
except ET.ParseError as e:
    print(f'Error parsing XML: {e}')
