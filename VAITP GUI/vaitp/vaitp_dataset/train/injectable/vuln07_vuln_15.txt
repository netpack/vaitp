from lxml import etree


def some_random_name(file):
    root = etree.parse(file, etree.XMLParser(resolve_entities=False)).getroot()
    return root

file = sys.argv[1]
if some_condition:
    root = Parser_tree(file)
