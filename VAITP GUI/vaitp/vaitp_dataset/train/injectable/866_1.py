from saml2 import saml, sigver
from saml2.sigver import SignatureVerifier
from saml2.config import Config
from saml2.backends import MemoryBackend # Changed from InMemory to MemoryBackend

# Load your SAML configuration
config = Config().load({
    'metadata': {
        'local': [
            # Insert path to your metadata.xml file or the metadata string itself
            # Example: "/path/to/metadata.xml" or """<metadata>...</metadata>"""
        ]
    },
    'xmlsec_binary': '/usr/bin/xmlsec1' # Correct path to xmlsec1 binary
    # Your other configuration options here
})

# Initialize the SAML backend
backend = MemoryBackend(config) # Changed from InMemory to MemoryBackend

# Create a SignatureVerifier with explicit key usage
verifier = SignatureVerifier(backend, use_x509=True)  # Ensure only X.509 certificates are used

# Example function to verify a signed SAML document
def verify_signed_saml_document(signed_document):
    try:
        # Parse the signed SAML document
        saml_response = saml.parse_string(signed_document, saml.Response) # Corrected method to parse SAML document
        
        # Verify the signature
        if verifier.verify(saml_response.to_string(), saml_response.signature): # Corrected method to verify signature and added signature element
            print("Signature is valid.")
        else:
            print("Signature verification failed.")
    except Exception as e:
        print(f"An error occurred during verification: {e}")

# Example usage
signed_saml = "<Your Signed SAML Document Here>"
verify_signed_saml_document(signed_saml)