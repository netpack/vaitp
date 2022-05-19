from lxml import etree

parser = etree.XMLParser(resolve_entities=True)
t = etree.parse('payload.xml', parser)
root = t.getroot()
print(etree.tostring(root, pretty_print=True))