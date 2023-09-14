import xml.dom.pulldom as pulldom

# XML input with a malicious external entity
xml_data = """
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
"""

# Create a pull parser with xml_pulldom
parser = pulldom.parseString(xml_data)

# Process the XML events
for event, node in parser:
    if event == pulldom.START_ELEMENT and node.localName == "foo":
        data = parser.expandNode(node)
        print(data)

