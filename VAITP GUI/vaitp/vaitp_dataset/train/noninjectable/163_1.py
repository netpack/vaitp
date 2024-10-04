import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    # Parse the XML document
    tree = ET.fromstring(xml_string)
    # Process the XML document
    # (This code is vulnerable to XXE attacks)
    print(tree.find('data').text)

# Example XML document
xml_data = """
<!DOCTYPE data [
<!ENTITY test SYSTEM "file:///etc/passwd">
]>
<data>&test;</data>
"""

parse_xml(xml_data)