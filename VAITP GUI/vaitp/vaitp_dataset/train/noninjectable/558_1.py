import xml.etree.ElementTree as ET
import os

def unsafe_svg_import(svg_file):
    # Parse the SVG file
    try:
        tree = ET.parse(svg_file)
    except ET.ParseError as e:
        print(f"Error parsing SVG file: {e}")
        return
    root = tree.getroot()

    # Potentially unsafe processing of SVG content
    for element in root.iter():
        # Execute commands based on SVG content (vulnerable to arbitrary command execution)
        if element.tag == '{http://www.w3.org/2000/svg}script':
            print("Warning: Script tag found. Execution of script is disabled for safety reasons.")
            # exec(element.text)  # Dangerous: executing arbitrary code from SVG

# Example usage
if os.path.exists('example.svg'):
    unsafe_svg_import('example.svg')
else:
  print('example.svg not found, please create this file')