import os
from xml.etree import ElementTree
# The following line sets the environment variable to disable the C accelerator
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
# The following line parses an XML document from a file
tree = ElementTree.parse('evil.xml')
# If evil.xml contains a specially-crafted XML document, this will not cause a DoS attack
root = tree.getroot()