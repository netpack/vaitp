import xml.etree.ElementTree as ET

def unsafe_svg2rlg(svg_data):
    # This code does not disable DTDs, making it vulnerable to XXE attacks
    root = ET.fromstring(svg_data)
    # Process the root element and convert to RLG (this part is hypothetical)
    return convert_svg_to_rlg(root)

def convert_svg_to_rlg(root):
    # Placeholder function for converting SVG to RLG
    pass