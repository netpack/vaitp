# Vulnerable code that imports the compromised 'democritus-html' package
# This code could potentially execute arbitrary code due to the backdoor.

import democritus_html  # Vulnerable import

def parse_xml_with_backdoor(xml_string):
    # This function may execute malicious code from the democritus-html package
    parsed_data = democritus_html.parse(xml_string)
    return parsed_data

# Example usage
xml_data = "<root><element>Hello World</element></root>"
parsed_xml = parse_xml_with_backdoor(xml_data)
print(parsed_xml)