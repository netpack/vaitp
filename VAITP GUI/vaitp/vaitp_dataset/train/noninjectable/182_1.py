# Vulnerable Python code using an older, vulnerable version of lxml
from lxml import etree

def parse_xml(xml_file):
    # Parse the XML file
    tree = etree.parse(xml_file)
    # Process the XML file
    # This is where the vulnerability can be exploited
    print(tree.find("//someElement").text)

# This could be a user-supplied file, leading to potential exploitation
parse_xml("user_supplied.xml")