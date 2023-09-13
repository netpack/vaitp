from xml.dom.expatbuilder import parseString

# XML data with a potentially malicious external entity
xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "/etc/passwd">
]>
<root>&xxe;</root>
"""

try:
    # Parse the XML data
    dom = parseString(xml_data)

    # Access and print the root element
    root = dom.documentElement
    print(root.tagName)
except Exception as e:
    print(f'Error parsing XML: {e}')
