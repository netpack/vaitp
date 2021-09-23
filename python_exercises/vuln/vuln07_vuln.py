from lxml import etree

parser = etree.XMLParser()
#parser = etree.XMLParser(resolve_entities=True) # Noncompliant
tree = etree.parse('vuln07_payload.xml', parser)
root = tree.getroot()
print(etree.tostring(root, pretty_print=True))