import xml.etree.ElementTree as ET
from defusedxml import ElementTree as SafeET

def parse_xml(xml_string, safe=True):
    if safe:
        try:
            root = SafeET.fromstring(xml_string)
        except SafeET.ParseError:
            return None
    else:
        try:
           root = ET.fromstring(xml_string)
        except ET.ParseError:
            return None
    return root

def get_data(xml_string, safe=True):
    root = parse_xml(xml_string, safe)
    if root is None:
        return None
    data = []
    for item in root.findall('item'):
        name = item.find('name').text
        value = item.find('value').text
        data.append({'name': name, 'value': value})
    return data