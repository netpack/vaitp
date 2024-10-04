# Import the xml.etree.ElementTree module
import xml.etree.ElementTree as ET

# Open a malicious XML file
xml_file = open("malicious.xml", "r")

# Parse the XML file
tree = ET.parse(xml_file)

# Close the file
xml_file.close()