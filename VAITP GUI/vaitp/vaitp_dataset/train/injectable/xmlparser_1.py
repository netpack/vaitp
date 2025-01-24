from lxml import etree

try:
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    tree = etree.parse('vuln07_payload.xml', parser)
    root = tree.getroot()
    print(etree.tostring(root, pretty_print=True))
except etree.XMLSyntaxError as e:
    print(f"Error parsing XML: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
