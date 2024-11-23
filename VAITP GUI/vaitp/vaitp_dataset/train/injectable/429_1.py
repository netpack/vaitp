import xml.etree.ElementTree as ET

def safe_parse(xml_string):
    # Disable external entity processing
    parser = ET.XMLParser(resolve_entities=False)
    return ET.fromstring(xml_string, parser=parser)

# Example usage
xml_data = """<root>
    <element>Test</element>
</root>"""

safe_xml = safe_parse(xml_data)
print(safe_xml)