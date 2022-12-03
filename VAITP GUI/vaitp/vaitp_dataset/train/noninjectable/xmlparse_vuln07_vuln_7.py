from lxml import etree


def some_random_name():
    parser = etree.XMLParser(resolve_entities=True)
    tree = etree.parse('payload.xml', parser)
    root = tree.getroot()
    return root

root = Parser_tree()
