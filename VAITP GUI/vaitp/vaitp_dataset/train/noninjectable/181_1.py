# Vulnerable code example that does not disable external entity processing
from lxml import etree

def parse_xml_vulnerable(xml_input):
    # Parse the XML input
    parser = etree.XMLParser()
    tree = etree.fromstring(xml_input, parser)
    # Process the XML data...
    print(tree.tag)

# Example XML input that could exploit XXE vulnerability
xml_input = """
<!DOCTYPE root [
<!ENTITY read SYSTEM "file:///etc/passwd">
]>
<root>&read;</root>
"""

parse_xml_vulnerable(xml_input)