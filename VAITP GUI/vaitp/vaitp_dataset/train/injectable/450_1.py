import xml.etree.ElementTree as ET
import re

def sanitize_xml(input_xml):
    # Basic sanitization to remove potentially harmful content
    # This could be extended with more sophisticated checks
    sanitized_xml = re.sub(r'<script.*?>.*?</script>', '', input_xml)
    return sanitized_xml

def process_xml(input_xml):
    try:
        # Sanitize the input XML before parsing
        sanitized_input = sanitize_xml(input_xml)
        root = ET.fromstring(sanitized_input)
        # Process the XML data
        for child in root:
            print(child.tag, child.text)
    except ET.ParseError as e:
        print("Error parsing XML:", e)

# Example of malicious XML input
malicious_input = "<data><item>Valid</item><item><script>alert('XSS')</script></item></data>"
process_xml(malicious_input)