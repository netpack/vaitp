import docx
from lxml import etree

# Create a malicious .docx file
malicious_doc = docx.Document()
malicious_doc.add_paragraph(
    """<?xml version="1.0"?>
    <!DOCTYPE root [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <root>
        <data>&xxe;</data>
    </root>"""
)
malicious_doc.save('malicious.docx')

# Load the document (safe code)
doc = docx.Document('safe.docx')

# Safely process the XML content
xml_content = doc.element.xml

# Custom function to safely parse XML
def safe_parse(xml_content):
    parser = etree.XMLParser(resolve_entities=False)  # Disable external entity resolution
    return etree.fromstring(xml_content, parser)

# Safely parse the XML content
try:
    safe_xml = safe_parse(xml_content)
    content = safe_xml.xpath('//w:p//w:t/text()')
    print(content)  # This will print the text without risk of XXE
except Exception as e:
    print(f"An error occurred: {e}")