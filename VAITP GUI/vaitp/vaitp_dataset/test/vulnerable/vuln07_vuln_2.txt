from lxml import etree

par = etree.XMLParser(resolve_entities=True)

if __name__ == '__main__':
    tr = etree.parse('payload.xml', par)
    our_root = tr.getroot()
    print(etree.tostring(our_root, pretty_print=True))