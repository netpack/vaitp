import xml.etree.ElementTree as ET

def vulnerable_parse_xml(xml_data):
    # This function represents a vulnerable XML parser
    # that does not handle malformed UTF-8 sequences correctly
    try:
        # Directly parsing XML data without validation
        tree = ET.fromstring(xml_data)
        return tree
    except Exception as e:
        print("Error:", e)
        return None

# Example of using the vulnerable XML parser
malicious_xml_data = b'<?xml version="1.0" encoding="UTF-8"?><root><element>\xED\xA0\x80</element></root>'
result = vulnerable_parse_xml(malicious_xml_data)
if result is not None:
    print("XML parsed successfully.")
else:
    print("Failed to parse XML.")