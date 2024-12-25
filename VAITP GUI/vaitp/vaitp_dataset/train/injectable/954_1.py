import fontTools.ttLib
from fontTools.ttLib import TTFont
from lxml import etree

def safe_parse_xml(xml_data):
    # Disable DTD and external entity processing to prevent XXE
    parser = etree.XMLParser(load_dtd=False, no_network=True)
    return etree.fromstring(xml_data, parser)

def parse_ot_svg_font(font_path):
    font = TTFont(font_path)
    if 'SVG ' in font:
        svg_table = font['SVG ']
        # Assuming svg_table is a bytes object containing XML data
        xml_data = svg_table.data # Access the raw byte data
        safe_xml = safe_parse_xml(xml_data)
        # Continue processing with safe_xml...
        return safe_xml
    else:
        return None
    

# Example usage
# parse_ot_svg_font('path/to/font.ot.svg')