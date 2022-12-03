from lxml import etree

parser = etree.XMLParser(resolve_entities=True)
tree = etree.parse('random_name.xml', parser)