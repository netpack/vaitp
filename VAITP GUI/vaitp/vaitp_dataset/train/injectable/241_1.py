import xml.etree.ElementTree as ET

# Safe XML parsing with external entities disabled
def parse_user_data_safe(xml_input):
    try:
        # Parse the XML with external entity loading disabled
        tree = ET.fromstring(xml_input, parser=ET.XMLParser(resolve_entities=False))
        
        # Convert to a dictionary or extract data as needed
        user_data = {}
        for element in tree:
            user_data[element.tag] = element.text
        return user_data
    except ET.ParseError as e:
        raise ValueError("Invalid XML input or parse error") from e


# Simulating an attacker-controlled XML input
attacker_xml = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">  <!-- Attacker-controlled entity -->
]>
<user>
  <name>&xxe;</name>  <!-- This will include the contents of /etc/passwd -->
</user>
"""

# Call the safe function
try:
    user_info = parse_user_data_safe(attacker_xml)
    print("User Info:", user_info)
except Exception as e:
    print("An error occurred:", e)