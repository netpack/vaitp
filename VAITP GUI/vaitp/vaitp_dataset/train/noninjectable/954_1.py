import fontTools.ttLib
from fontTools.ttLib import TTFont
from lxml import etree

def parse_ot_svg_font(font_path):
    font = TTFont(font_path)
    svg_table = font['SVG '].table
    # Assuming svg_table is a string containing XML data
    xml_data = svg_table.toXML()  # This is a placeholder for actual SVG table extraction
    # Vulnerable XML parsing that allows external entities
    xml_tree = etree.fromstring(xml_data.encode('utf-8'))
    # Continue processing with xml_tree...

# Example usage
# parse_ot_svg_font('path/to/font.ot.svg')