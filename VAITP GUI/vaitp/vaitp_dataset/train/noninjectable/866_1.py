```
```python
from saml2 import saml
from saml2.sigver import SignatureVerifier
from saml2.config import Config
from saml2.entity import Entity

# Load your SAML configuration
config = Config()
config.load({
    "xmlsec_binary": "/usr/bin/xmlsec1",
    "metadata": {
      "local": ["/path/to/your/metadata.xml"] # Replace with actual path
    },
    "service": {
        "sp": {
            "endpoints": {
                "assertion_consumer_service": [
                    ("https://example.com/acs", saml.BINDING_HTTP_POST)
                ],
            },
            "required_attributes": ["uid"],
            "name": "ExampleSP",
        },
    },
    "key_file": "/path/to/your/signing.key",  # Replace with actual path to your private key
    "cert_file": "/path/to/your/signing.crt",  # Replace with actual path to your certificate
})

# Initialize the SAML entity with the loaded config
backend = Entity(config)

# Create a SignatureVerifier without explicit key usage restrictions
verifier = SignatureVerifier(config.xmlsec_binary, backend)  # Pass the backend entity


# Example function to verify a signed SAML document
def verify_signed_saml_document(signed_document):
    try:
        # Parse the signed SAML document
        saml_response = saml.response_from_string(signed_document, backend.config, None)
        
        # Verify the signature
        if verifier.verify_signature(saml_response):
            print("Signature is valid.")
        else:
            print("Signature verification failed.")
    except Exception as e:
        print(f"An error occurred during verification: {e}")

# Example usage
signed_saml = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="s268e685a749a05c515647e1b442471e16c5e50d9"
    Version="2.0" IssueInstant="2024-01-26T15:34:36Z" Destination="https://example.com/acs"
    InResponseTo="id-4f2d6199-13cf-4f6b-91b9-d15a6f79854a">
    <saml:Issuer>https://example.com/idp</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="s295f91f7240f5116721e288c20a1c2a16d9e7abf"
        Version="2.0" IssueInstant="2024-01-26T15:34:36Z">
        <saml:Issuer>https://example.com/idp</saml:Issuer>
        <saml:Subject>
            <saml:NameID>user123</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData InResponseTo="id-4f2d6199-13cf-4f6b-91b9-d15a6f79854a"
                    Recipient="https://example.com/acs"
                    NotOnOrAfter="2024-01-26T15:39:36Z"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="2024-01-26T15:34:36Z"
            NotOnOrAfter="2024-01-26T15:39:36Z">
            <saml:AudienceRestriction>
                <saml:Audience>https://example.com/sp</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="2024-01-26T15:34:36Z"
            SessionIndex="s268e685a749a05c515647e1b442471e16c5e50d9">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>
                    urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
                </saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
                <saml:AttributeValue xsi:type="xs:string">user123</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>"""
verify_signed_saml_document(signed_saml)