from lxml import etree


def some_random_name(file):
    parser = etree.XMLParser(resolve_entities=False)
    tree = etree.parse(file, parser)
    root = tree.getroot()
    return root

file = sys.argv[1]
if some_condition:
    root = Parser_tree(file)
