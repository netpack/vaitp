from lxml import etree

parser = etree.XMLParser(resolve_entities=False)
#comment 1
tree = etree.parse('vuln07_payload.xml', parser)
#comment 2
root = tree.getroot()
#comment 3