import xml.etree.ElementTree as ET

def parse_xml_vulnerable(xml_input):
    # Parse the XML input
    tree = ET.parse(xml_input)
    root = tree.getroot()
    # Process the XML data
    print("Processing XML data...")
    for elem in root:
        print(elem.tag, elem.text)

# Example usage with a file containing XML data
xml_file = 'example.xml' # An XML file that could contain dangerous external entities
parse_xml_vulnerable(xml_file)