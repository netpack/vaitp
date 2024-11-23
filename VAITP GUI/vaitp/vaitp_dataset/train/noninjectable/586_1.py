import xml.etree.ElementTree as ET

def to_color(arg):
    # Vulnerable code: using eval on user input
    return eval(arg)

def parse_xml(xml_string):
    root = ET.fromstring(xml_string)
    for span in root.findall('.//span'):
        color = span.get('color')
        if color:
            # This line is vulnerable to remote code execution
            safe_color = to_color(color)
            # Proceed with using safe_color

# Example usage
xml_input = '<root><span color="__import__(\'os\').system(\'ls\')">Hello</span></root>'
parse_xml(xml_input)