# Import the xml.etree.ElementTree module
import xml.etree.ElementTree as ET

# Define a valid XML input
# This input has a DTD declaration followed by a comment
# The comment is allowed in a DTD
xml = "<?xml version='1.0'?>\n"
      "<!DOCTYPE foo [\n"
      "<!ELEMENT foo ANY>\n"
      "]>\n"
      "<!-- This is a comment -->"

# Try to parse the XML input using the ET.fromstring() function
# This will not trigger the vulnerability and cause a buffer over-read
root = ET.fromstring(xml)

# Try to get the current line number
# This will return a valid value
line = root.sourceline

# Print the line number
print(line) # This will print 6