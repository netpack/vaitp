from lxml import etree

def parse_xml_patched(xml_data):
    # Parse the XML data with external entity processing disabled
    parser = etree.XMLParser(no_network=True, resolve_entities=False)
    tree = etree.fromstring(xml_data, parser)
    # Process the XML tree...
    print(tree.tag)

# XML data remains the same, but the exploit will not work
xml_data = """
<!DOCTYPE root [
<!ENTITY read SYSTEM "file:///etc/passwd">
]>
<root>&read;</root>
"""

parse_xml_patched(xml_data)