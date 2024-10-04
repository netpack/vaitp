from defusedxml.ElementTree import parse

def parse_xml_secure(xml_input):
    # Parse the XML input securely
    tree = parse(xml_input)
    root = tree.getroot()
    # Process the XML data securely
    print("Processing XML data securely...")
    for elem in root:
        print(elem.tag, elem.text)

# Example usage with a file containing XML data
xml_file = 'example.xml'
parse_xml_secure(xml_file)