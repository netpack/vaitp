# Vulnerable version of the code that executes arbitrary code from XML
import xml.etree.ElementTree as ET

def vulnerable_parse_xml(xml_string):
    # This method can execute code embedded in the XML
    exec(xml_string)

# Example usage
xml_data = "<root><child>Some data</child><script>print('Executing arbitrary code!')</script></root>"
vulnerable_parse_xml(xml_data)