# This will only work if xml_bad_cElementTree is available in your Python installation
from xml.etree import ElementTree as ET

# XML data with a potentially malicious external entity
xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "/etc/passwd">
]>
<root>&xxe;</root>
"""

try:
    root = ET.fromstring(xml_data)

    for element in root.findall('element'):
        print(element.text)
except ET.ParseError as e:
    print(f'Error parsing XML: {e}')
