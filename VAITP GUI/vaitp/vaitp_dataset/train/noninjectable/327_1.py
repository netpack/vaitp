# Vulnerable version of d8s-xml that allows potential code execution
import xml.etree.ElementTree as ET

def unsafe_parse_xml(xml_string):
    # This method uses eval() or similar unsafe functions which can lead to code execution
    root = ET.fromstring(xml_string)
    # Potentially unsafe operation that could execute arbitrary code
    exec("print('Executing arbitrary code!')")
    return root

# Example usage
xml_data = """<root><element>Sample Data</element></root>"""
parsed_xml = unsafe_parse_xml(xml_data)
print(parsed_xml)