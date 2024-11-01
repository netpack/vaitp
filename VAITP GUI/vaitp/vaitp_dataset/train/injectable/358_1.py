import xml.etree.ElementTree as ET

def validate(xml_input):
    # Use a parser that disables external entity processing
    parser = ET.XMLParser(resolve_entities=False)
    tree = ET.fromstring(xml_input, parser=parser)
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

# Now this will not read sensitive file contents
validate(malicious_input)