import xml.etree.ElementTree as ET
import xmlsec
import os

def validate_saml_response(saml_response):
    # Parse the SAML response
    try:
        root = ET.fromstring(saml_response)
    except ET.ParseError:
        print("Error parsing SAML response XML")
        return False

    # Canonicalize the XML using exclusive canonicalization before signing
    try:
        xml_data = xmlsec.tree.canonicalize(root, xmlsec.TransformExclC14N)
    except Exception as e:
       print(f"Error canonicalizing XML: {e}")
       return False


    # Verify the signature with proper context
    try:
        # Ensure the public key file exists
        public_key_path = 'path/to/public_key.pem'
        if not os.path.exists(public_key_path):
            print(f"Error: Public key file not found at {public_key_path}")
            return False
        
        key = xmlsec.Key.from_file(public_key_path, xmlsec.KeyFormat.PEM)
        signature_context = xmlsec.SignatureContext()
        signature_context.key = key


        # Find the signature element
        signature_node = root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
        if signature_node is None:
             print("Error: Signature node not found in SAML response.")
             return False

        
        # Verify the signature using the existing signature node
        signature_context.verify(signature_node)


    except xmlsec.Error as e:
        print(f"Error verifying signature: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during signature validation: {e}")
        return False

    # If verification is successful, process the SAML response
    return True

# Example usage
saml_response = '''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
                             xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
                             ID="response1" Version="2.0" 
                             IssueInstant="2024-01-12T12:00:00Z" 
                             Destination="https://sp.example.com/acs">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                    xmlns:xs="http://www.w3.org/2001/XMLSchema" 
                    ID="assertion1" Version="2.0" 
                    IssueInstant="2024-01-12T12:00:00Z">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">user123</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="2024-01-12T12:05:00Z" 
                                             Recipient="https://sp.example.com/acs" 
                                             InResponseTo="request1"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="2024-01-12T12:00:00Z" NotOnOrAfter="2024-01-12T12:05:00Z">
            <saml:AudienceRestriction>
                <saml:Audience>https://sp.example.com</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="2024-01-12T12:00:00Z" SessionIndex="session1">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        
    </saml:Assertion>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#assertion1">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>some_digest_value_here</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>some_signature_value_here</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>
                    MII...
                </ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>

</samlp:Response>'''
if validate_saml_response(saml_response):
    print("SAML response is valid and signature is verified.")
else:
    print("Invalid SAML response or signature.")