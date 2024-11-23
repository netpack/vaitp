import xml.etree.ElementTree as ET

def safe_load_xml(xml_string):
    # Parse the XML string safely
    try:
        root = ET.fromstring(xml_string)
        # Process the XML without using eval
        return root
    except ET.ParseError as e:
        print("Invalid XML:", e)

# Example of safe XML input
xml_input = """<root>
    <data>Safe data</data>
</root>"""

safe_load_xml(xml_input)