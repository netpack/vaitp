import xml.etree.ElementTree as ET

# XML data, potentially with malicious entities
xml_data = """
<root>
  <example>Safe example</example>
</root>
"""

# Create a safe parser that disables external entity processing
parser = ET.XMLParser(resolve_entities=False)

# Parsing the XML data safely with the custom parser
tree = ET.fromstring(xml_data, parser=parser)