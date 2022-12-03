from lxml import etree

parser = etree.XMLParser(resolve_entities=False)
tree = etree.parse('random_name.xml', parser)