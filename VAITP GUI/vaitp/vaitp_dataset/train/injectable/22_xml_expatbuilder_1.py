import xml.dom.expatbuilder

# XML data with a potentially malicious external entity
xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "/etc/passwd">
]>
<root>&xxe;</root>
"""

try:
    # Create an ExpatBuilder and set the external entity handler to None
    builder = xml.dom.expatbuilder.ExpatBuilder()
    builder.entity = None
    
    # Parse the XML data
    dom = builder.parseString(xml_data)

    # Access and print the root element
    root = dom.documentElement
    print(root.tagName)
except Exception as e:
    print(f'Error parsing XML: {e}')
