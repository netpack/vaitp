from lxml import etree

def parse_xml_vulnerable(xml_data):
    # Parse the XML data
    parser = etree.XMLParser()
    tree = etree.fromstring(xml_data, parser)
    # Process the XML tree...
    print(tree.tag)

# Example of dangerous XML data that could exploit the vulnerability
xml_data = """
<!DOCTYPE root [
<!ENTITY read SYSTEM "file:///etc/passwd">
]>
<root>&read;</root>
"""

parse_xml_vulnerable(xml_data)