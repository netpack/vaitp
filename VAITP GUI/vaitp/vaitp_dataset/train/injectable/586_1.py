import xml.etree.ElementTree as ET

def safe_to_color(color_string):
    # Implement a safe parsing mechanism to prevent code execution
    # For example, validate against a list of allowed colors
    allowed_colors = {'red', 'green', 'blue', 'black', 'white'}
    if color_string in allowed_colors:
        return color_string
    else:
        raise ValueError("Invalid color specified")

def parse_xml(xml_string):
    root = ET.fromstring(xml_string)
    for span in root.findall('.//span'):
        color = span.get('color')
        if color:
            try:
                safe_color = safe_to_color(color)
                # Proceed with using safe_color
            except ValueError as e:
                print(f"Error: {e}")

# Example usage
xml_input = '<root><span color="red">Hello</span></root>'
parse_xml(xml_input)