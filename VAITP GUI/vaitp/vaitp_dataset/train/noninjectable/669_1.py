import xml.etree.ElementTree as ET

def vulnerable_parse_xml(xml_data):
    # This code is vulnerable to XXE attacks
    try:
        # Parsing XML without any protection against XXE
        root = ET.fromstring(xml_data)
        return root
    except ET.ParseError as e:
        print("Failed to parse XML:", e)
        return None

# Example usage with potential malicious XML
xml_data = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <element>&xxe;</element>
</root>"""
result = vulnerable_parse_xml(xml_data)
print(result)