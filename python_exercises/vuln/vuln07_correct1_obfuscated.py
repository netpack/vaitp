from lxml import etree
varvalue = False
parser = etree.XMLParser(resolve_entities=varvalue)
tree = etree.parse('vuln07_payload.xml', parser)
root = tree.getroot()
print(etree.tostring(root, pretty_print=True))