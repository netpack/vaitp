from lxml import etree

def Parser_tree(parser, tree):
    root = tree.getroot()
    return root

parser = etree.XMLParser(resolve_entities=False,load_dtd=False)