import xml.dom.minidom

# XML input with a malicious external entity
xml_data = """
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
"""

# Parse the XML using xml_minidom with external entity expansion disabled
dom = xml.dom.minidom.parseString(xml_data, expand_entities=False)

# Extract and print the content of the parsed XML
print(dom.toxml())
