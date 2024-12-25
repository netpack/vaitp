from lxml import etree
from plone.api import portal

def handle_upload(xml_data):
    if portal.get().has_permission('Manage portal', portal.get()):
        # Vulnerable XML parsing that allows XXE
        parser = etree.XMLParser(resolve_entities=False)
        parsed_data = etree.fromstring(xml_data.encode('utf-8'), parser=parser)

        # Process the parsed data
        # ...