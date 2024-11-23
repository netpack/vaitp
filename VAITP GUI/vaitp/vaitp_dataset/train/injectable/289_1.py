# Fixed version of the code that no longer imports the vulnerable package
# Instead of using the compromised 'democritus-html' package, we use a safe alternative.

# Safe import
import xml.etree.ElementTree as ET  # Using built-in XML library

def safe_parse_xml(xml_string):
    try:
        # Parse the XML safely
        root = ET.fromstring(xml_string)
        return root
    except ET.ParseError as e:
        print("Error parsing XML:", e)
        return None

# Example usage
xml_data = "<root><element>Hello World</element></root>"
parsed_xml = safe_parse_xml(xml_data)
print(parsed_xml)