from lxml import etree

f = str(sys.argv[1])
parser = etree.XMLParser(resolve_entities=True)
tree = etree.parse(f, parser)