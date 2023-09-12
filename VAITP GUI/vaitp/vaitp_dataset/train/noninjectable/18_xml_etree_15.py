from lxml import etree

tree = etree.parse('vuln07_payload.xml',  etree.XMLParser(resolve_entities=True))
root = tree.getroot()