# Fixed version of d8s-xml that ensures no unauthorized code execution
import xml.etree.ElementTree as ET

def safe_parse_xml(xml_string):
    try:
        # Parse the XML safely
        root = ET.fromstring(xml_string)
        return root
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return None

# Example usage
xml_data = """<root><element>Sample Data</element></root>"""
parsed_xml = safe_parse_xml(xml_data)
print(parsed_xml)