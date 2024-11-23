import xml.etree.ElementTree as ET

def safe_eval(expression):
    # Implement a safe evaluation mechanism, avoiding eval
    # For example, you could use a whitelist of allowed operations or a library like ast.literal_eval
    return eval(expression)  # Replace this with a safer alternative

def process_xml_input(xml_input):
    try:
        root = ET.fromstring(xml_input)
        # Process the XML safely
        for elem in root.iter():
            # Only allow certain tags or attributes to be processed
            if elem.tag not in ['allowed_tag1', 'allowed_tag2']:
                raise ValueError("Invalid XML tag detected.")
            # Handle the element as needed
    except ET.ParseError:
        raise ValueError("Invalid XML input.")

# Example usage
xml_input = "<root><allowed_tag1>Data</allowed_tag1></root>"
process_xml_input(xml_input)