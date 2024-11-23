import lxml.etree as ET

def safe_parse_xmp(xmp_data):
    parser = ET.XMLParser(recover=False, no_network=True)
    return ET.fromstring(xmp_data.encode('utf-8'), parser)

# Example usage
xmp_data = """<xmpmeta>
    <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
        <rdf:Description rdf:about="http://example.com">
            <dc:title>Example Title</dc:title>
        </rdf:Description>
    </rdf:RDF>
</xmpmeta>"""

try:
    parsed_xmp = safe_parse_xmp(xmp_data)
    print(ET.tostring(parsed_xmp, pretty_print=True).decode())
except ET.XMLSyntaxError as e:
    print("Failed to parse XMP data:", e)