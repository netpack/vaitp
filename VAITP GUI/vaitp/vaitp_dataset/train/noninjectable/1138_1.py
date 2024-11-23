import xml.etree.ElementTree as ET

def load_xml_and_execute(xml_string):
    # Parse the XML string
    root = ET.fromstring(xml_string)
    
    # Unsafe execution of code found in the XML
    code_to_execute = root.find('code').text
    eval(code_to_execute)

# Example of malicious XML input
malicious_xml = """<root>
    <code>print('This is an arbitrary code execution!')</code>
</root>"""

load_xml_and_execute(malicious_xml)