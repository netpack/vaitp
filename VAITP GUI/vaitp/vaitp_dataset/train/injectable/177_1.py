import xml.etree.ElementTree as ET

def parse_xml_safe(xml_string):
    # Patched XML parsing function that disables external entity processing
    parser = ET.XMLParser(target=ET.TreeBuilder(), resolve_entities=False)
    tree = ET.fromstring(xml_string, parser=parser)
    for elem in tree.iter():
        print(elem.tag, elem.text)

# The same XML string as before, but now the XXE attack will not work
xml_string = """
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<creds>
    <user>&xxe;</user>
    <pass>bar</pass>
</creds>
"""

parse_xml_safe(xml_string)