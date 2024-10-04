# Import the xml.etree.ElementTree module
import xml.etree.ElementTree as ET

# Open a malicious XML file
xml_file = open("malicious.xml", "r")

# Parse the XML file and handle the exception
try:
    tree = ET.parse(xml_file)
except ET.XMLSyntaxError:
    print("Denial-of-service detected, aborting.")
    
# Close the file
xml_file.close()