import zipfile
import xml.etree.ElementTree as ET

def safe_import_kmz(file_path):
    # Ensure the file is a valid KMZ (zip) file
    if not zipfile.is_zipfile(file_path):
        raise ValueError("Invalid KMZ file")

    with zipfile.ZipFile(file_path, 'r') as kmz:
        # Extract KML file from KMZ
        kml_files = [name for name in kmz.namelist() if name.endswith('.kml')]
        if not kml_files:
            raise ValueError("No KML file found in KMZ")

        # Read the KML file safely
        with kmz.open(kml_files[0]) as kml_file:
            kml_content = kml_file.read()

        # Parse the KML content using ElementTree
        try:
            root = ET.fromstring(kml_content)
            # Process the KML content safely without eval
            process_kml(root)
        except ET.ParseError as e:
            raise ValueError("Error parsing KML: {}".format(e))

def process_kml(root):
    # Implement your KML processing logic here
    # Avoid using eval or exec on any user-controlled data
    for placemark in root.findall('.//Placemark'):
        name = placemark.find('name').text
        print(f"Processing placemark: {name}")