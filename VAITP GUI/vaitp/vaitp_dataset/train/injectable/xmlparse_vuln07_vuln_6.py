from lxml import etree


def Parser_tree():
    parser = etree.XMLParser(resolve_entities=False)
    tree = etree.parse('payload.xml', parser)
    root = tree.getroot()
    return root

root = Parser_tree()
print(etree.tostring(root, pretty_print=True))