import xml.etree.ElementTree as ET

def safe_parse_xml(xml_data):
    # Use the default XML parser which is safe against XXE
    try:
        root = ET.fromstring(xml_data)
        return root
    except ET.ParseError as e:
        print("Failed to parse XML:", e)
        return None

# Example usage
xml_data = """<root><element>Test</element></root>"""
result = safe_parse_xml(xml_data)
print(result)