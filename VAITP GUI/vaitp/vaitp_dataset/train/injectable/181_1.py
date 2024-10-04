# Patched code example that disables external entity processing
from lxml import etree

def parse_xml_secure(xml_input):
    # Parse the XML input securely by disabling external entities
    parser = etree.XMLParser(no_network=True, resolve_entities=False)
    tree = etree.fromstring(xml_input, parser)
    # Process the XML data securely...
    print(tree.tag)

# Example XML input that could have exploited XXE vulnerability
xml_input = """
<!DOCTYPE root [
<!ENTITY read SYSTEM "file:///etc/passwd">
]>
<root>&read;</root>
"""

parse_xml_secure(xml_input)