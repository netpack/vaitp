import xml.etree.ElementTree as ET
from xmlsec import SignatureContext, Template, Transform, Key

def validate_saml_response(saml_response):
    # Parse the SAML response
    root = ET.fromstring(saml_response)

    # Ensure that the XML is canonicalized correctly
    canonicalized_xml = ET.tostring(root, method='xml', encoding='utf-8')

    # Verify the signature
    key = Key.from_file('path/to/public_key.pem', xmlsec.KeyFormat.PEM)
    signature_context = SignatureContext(key)
    
    # Create a signature template
    signature_template = Template(root)
    signature_context.verify(signature_template)

    # If verification is successful, process the SAML response
    return True

# Example usage
saml_response = '''<samlp:Response ...>...</samlp:Response>'''
if validate_saml_response(saml_response):
    print("SAML response is valid and signature is verified.")
else:
    print("Invalid SAML response or signature.")