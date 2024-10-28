import untangled
import xml.etree.ElementTree as ET

def is_valid_xml(xml_string):
    # Simple validation to check if the XML is well-formed
    try:
        ET.fromstring(xml_string)
        return True
    except ET.ParseError:
        return False

def safe_parse_xml(xml_string):
    if not is_valid_xml(xml_string):
        raise ValueError("Invalid XML input")

    # Proceed to parse the XML safely using untangled
    obj = untangled.parse(xml_string)
    return obj

# Example of a vulnerable XML string (this is just a placeholder for the sake of example)
vulnerable_xml = "<root><element>Some data</element></root>"

try:
    result = safe_parse_xml(vulnerable_xml)
    print("Parsed XML:", result)
except ValueError as e:
    print("Error:", e)
except Exception as e:
    print("An unexpected error occurred:", e)