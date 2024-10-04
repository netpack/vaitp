from xml.etree import ElementTree
# The following line parses an XML document from a file
tree = ElementTree.parse('evil.xml')
# If evil.xml contains a specially-crafted XML document, this will cause a DoS attack
root = tree.getroot()