import xml.etree.ElementTree as ET

def vulnerable_parse(xml_string):
    # This code does not disable external entity processing
    return ET.fromstring(xml_string)

# Example usage with a potentially malicious XML
xml_data = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
    <element>&xxe;</element>
</root>"""

vulnerable_xml = vulnerable_parse(xml_data)
print(vulnerable_xml)