import zipfile
import xml.etree.ElementTree as ET

def import_kmz(file_path):
    # Assume the file is a valid KMZ (zip) file
    with zipfile.ZipFile(file_path, 'r') as kmz:
        # Extract KML file from KMZ
        kml_files = [name for name in kmz.namelist() if name.endswith('.kml')]
        if not kml_files:
            raise ValueError("No KML file found in KMZ")

        # Read the KML file
        with kmz.open(kml_files[0]) as kml_file:
            kml_content = kml_file.read()

        # Parse the KML content as XML
        try:
            root = ET.fromstring(kml_content)
            # Process the KML content as needed. 
            # Example: Print the root tag
            print(root.tag)
        except ET.ParseError:
             raise ValueError("Invalid KML file content")

# Example usage
# import_kmz('path/to/crafted.kmz')