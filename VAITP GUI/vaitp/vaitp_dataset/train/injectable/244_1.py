import untangle
import re

# Function to validate XML data
def is_valid_xml(xml_data):
    # Basic validation: Check for well-formedness and disallow certain patterns
    if not isinstance(xml_data, str):
        return False
    # Example: Disallow recursive entity references (basic check)
    if re.search(r'<!ENTITY\s+\w+\s+<!ENTITY', xml_data):
        return False
    return True

# Function to process XML safely
def process_xml(xml_data):
    # Validate and sanitize the XML data
    if not is_valid_xml(xml_data):
        raise ValueError('Invalid XML data')

    # Process the sanitized XML
    try:
        obj = untangle.parse(xml_data)
        # ... rest of the code to work with the parsed object ...
        return obj
    except Exception as e:
        print(f"Error processing XML: {e}")
        return None

# Example XML input (for demonstration purposes)
xml_input = """
<root>
    <element>Some data</element>
</root>
"""

# Usage
try:
    parsed_object = process_xml(xml_input)
    if parsed_object:
        print("XML processed successfully:")
        print(parsed_object)
    else:
        print("Failed to process XML.")
except ValueError as ve:
    print(ve)