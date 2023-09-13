import xml.etree.ElementTree as ET

# XML data with a potentially malicious external entity
xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "/etc/passwd">
]>
<root>&xxe;</root>
"""

try:
    # Define a custom parser with entity expansion disabled
    parser = ET.XMLParser()
    parser.entity = {}
    
    # Parse the XML data using the custom parser
    root = ET.fromstring(xml_data, parser=parser)

    for element in root.findall('element'):
        print(element.text)
except ET.ParseError as e:
    print(f'Error parsing XML: {e}')
