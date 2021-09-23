from lxml import etree
import html

parser = etree.XMLParser()
#parser = etree.XMLParser(resolve_entities=True) # Noncompliant
tree = etree.parse('vuln07_payload.xml', parser)
root = tree.getroot()
#escaped_root = html.escape(root)
print(etree.tostring(html.escape(root), pretty_print=False))