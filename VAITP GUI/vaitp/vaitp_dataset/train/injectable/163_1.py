import xml.etree.ElementTree as ET

def parse_xml_safe(xml_string):
    # Create a custom parser that disables external entity processing
    parser = ET.XMLParser(resolve_entities=False)
    # Parse the XML document using the safe parser
    tree = ET.fromstring(xml_string, parser=parser)
    # Process the XML document safely
    print(tree.find('data').text)

# Example XML document
xml_data_safe = """
<data>Hello, world!</data>
"""

parse_xml_safe(xml_data_safe)