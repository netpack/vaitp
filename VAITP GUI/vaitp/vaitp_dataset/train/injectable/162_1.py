import xml.etree.ElementTree as ET
from xml.parsers.expat import ParserCreate

# This function configures a secure XML parser that does not process external entities
def secure_elementtree_parse(xml_data):
    # Create a custom parser that ignores external entities
    parser = ET.XMLParser(target=ET.TreeBuilder())
    parser.parser.UseForeignDTD(False)
    parser.entity = {}
    # Parse the XML securely
    return ET.fromstring(xml_data, parser=parser)

# Same XML data as before
xml_data = """
<!DOCTYPE bomb [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<start>&lol9;</start>
"""

tree = secure_elementtree_parse(xml_data)
print(tree.tag)