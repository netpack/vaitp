from lxml import etree

f = str(sys.argv[1])
parser = etree.XMLParser(resolve_entities=False)
tree = etree.parse(f, parser)