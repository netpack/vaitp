import xml.etree.ElementTree as ET
import os

def unsafe_svg_import(svg_file):
    # Parse the SVG file
    tree = ET.parse(svg_file)
    root = tree.getroot()

    # Potentially unsafe processing of SVG content
    for element in root.iter():
        # Execute commands based on SVG content (vulnerable to arbitrary command execution)
        if element.tag == 'script':
            exec(element.text)  # Dangerous: executing arbitrary code from SVG

# Example usage
unsafe_svg_import('example.svg')