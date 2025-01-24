import xdg.Menu
import tempfile
import xml.etree.ElementTree as ET

# Sanitize the input before parsing
def sanitize_menu_file(menu_file):
    try:
        tree = ET.parse(menu_file)
        root = tree.getroot()
        for category in root.findall(".//Category"):
            root.remove(category)
    
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp_file:
            tree.write(tmp_file, encoding='utf-8', xml_declaration=True)
            tmp_file_path = tmp_file.name
            
        return tmp_file_path
    except ET.ParseError:
        return None

# Parse the sanitized .menu file
sanitized_file = sanitize_menu_file('safe.menu')
if sanitized_file:
    menu = xdg.Menu.parse(sanitized_file)