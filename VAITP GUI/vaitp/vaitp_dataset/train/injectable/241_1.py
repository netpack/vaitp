import easyxml

# Safe XML parsing with external entities disabled
def parse_user_data_safe(xml_input):
    # Create a parser with external entities disabled (hypothetical method)
    parser = easyxml.XMLParser()
    parser.disable_external_entities()  # Hypothetical method to disable external entities
    user_data = parser.parse(xml_input)
    return user_data

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
    print("User  Info:", user_info)
except Exception as e:
    print("An error occurred:", e)