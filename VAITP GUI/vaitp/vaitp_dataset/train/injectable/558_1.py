import xml.etree.ElementTree as ET

def safe_svg_import(svg_file):
    # Parse the SVG file safely
    try:
        tree = ET.parse(svg_file)
        root = tree.getroot()

        # Process the SVG content without executing arbitrary code
        for element in root.iter():
            # Handle SVG elements as needed, but avoid executing any commands
            print(f"Processing element: {element.tag}")

    except ET.ParseError as e:
        print(f"Error parsing SVG file: {e}")

# Example usage
safe_svg_import('example.svg')