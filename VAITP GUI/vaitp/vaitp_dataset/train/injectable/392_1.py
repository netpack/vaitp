import xml.etree.ElementTree as ET

def safe_parse_xml(xml_data):
    try:
        # Use ElementTree to parse the XML data safely
        tree = ET.fromstring(xml_data)
        return tree
    except ET.ParseError as e:
        print("XML Parse Error:", e)
        return None

# Example of using the safe XML parser
xml_data = b'<?xml version="1.0" encoding="UTF-8"?><root><element>Test</element></root>'
result = safe_parse_xml(xml_data)
if result is not None:
    print("XML parsed successfully.")
else:
    print("Failed to parse XML.")