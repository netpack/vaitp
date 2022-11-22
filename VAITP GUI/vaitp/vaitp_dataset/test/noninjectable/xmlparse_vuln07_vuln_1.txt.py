from lxml import etree

par = etree.XMLParser(resolve_entities=True)
tr = etree.parse('payload.xml', par)
our_root = tr.getroot()
print(etree.tostring(our_root, pretty_print=True))