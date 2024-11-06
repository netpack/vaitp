import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    # This code is vulnerable to XXE
    root = ET.fromstring(xml_string)
    return root

# Example of malicious XML input
malicious_xml = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>"""

try:
    result = parse_xml(malicious_xml)
    print(result.find('data').text)  # This would output the contents of /etc/passwd
except Exception as e:
    print(f"Error: {e}")