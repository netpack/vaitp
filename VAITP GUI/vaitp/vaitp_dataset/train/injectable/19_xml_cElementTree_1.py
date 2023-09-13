import xml.etree.ElementTree as ET

# XML data with a potentially malicious external entity
xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "/etc/passwd">
]>
<root>&xxe;</root>
"""

try:
    parser = ET.XMLParser()
    parser.entity = {}
    root = ET.fromstring(xml_data, parser=parser)

    for element in root.findall('element'):
        print(element.text)
except ET.ParseError as e:
    print(f'Error parsing XML: {e}')
