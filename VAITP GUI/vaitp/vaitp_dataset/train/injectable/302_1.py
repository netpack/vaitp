# Fixed version of the code that avoids executing arbitrary code
import xml.etree.ElementTree as ET

def safe_parse_xml(xml_string):
    try:
        # Safely parse the XML string without executing any embedded code
        root = ET.fromstring(xml_string)
        return root
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")

# Example usage
xml_data = "<root><child>Some data</child></root>"
parsed_data = safe_parse_xml(xml_data)
print(parsed_data)