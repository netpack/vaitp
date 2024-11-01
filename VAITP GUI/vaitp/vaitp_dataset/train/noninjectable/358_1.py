import xml.etree.ElementTree as ET

def validate(xml_input):
    # Directly parsing user input
    tree = ET.fromstring(xml_input)
    # Further processing...
    return tree

# Example of a potentially malicious XML input
malicious_input = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
"""

# This could read sensitive file contents
validate(malicious_input)