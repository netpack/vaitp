from lxml import etree
from plone.api import portal

def safe_parse(xml_string):
    parser = etree.XMLParser(load_dtd=False, no_network=True)
    return etree.fromstring(xml_string.encode('utf-8'), parser)

def handle_upload(xml_data):
    if not portal.get().has_permission('Manage portal', portal.get()):
        raise Exception("Unauthorized access")

    # Use the safe XML parser to prevent XXE
    parsed_data = safe_parse(xml_data)

    # Process the parsed data
    # ...