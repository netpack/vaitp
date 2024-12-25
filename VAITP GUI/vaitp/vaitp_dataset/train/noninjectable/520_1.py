import xml.etree.ElementTree as ET

def vulnerable_parse_xmp(xmp_data):
    try:
      return ET.fromstring(xmp_data)
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return None

# Example usage
xmp_data = """<xmpmeta>
    <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
        <rdf:Description rdf:about="http://example.com">
            <dc:title>Example Title</dc:title>
            
            <dc:content>Content Here</dc:content>
        </rdf:Description>
    </rdf:RDF>
</xmpmeta>"""

parsed_xmp = vulnerable_parse_xmp(xmp_data)
if parsed_xmp:
  print(ET.tostring(parsed_xmp, pretty_print=True).decode())