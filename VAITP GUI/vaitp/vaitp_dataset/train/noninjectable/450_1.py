import xml.etree.ElementTree as ET

def process_xml(input_xml):
    try:
        # Directly parsing the input XML
        root = ET.fromstring(input_xml)
        # Process the XML data
        for child in root:
            print(child.tag, child.text)
    except ET.ParseError as e:
        print("Error parsing XML:", e)

# Example of malicious XML input
malicious_input = "<data><item>Valid</item><item><script>alert('XSS')</script></item></data>"
process_xml(malicious_input)