from saml2 import saml
from saml2.sigver import SignatureVerifier
from saml2.config import Config
from saml2.backend import InMemory

# Load your SAML configuration
config = Config().load({
    # Your configuration options here
})

# Initialize the SAML backend with default settings
backend = InMemory(config)

# Create a SignatureVerifier without explicit key usage restrictions
verifier = SignatureVerifier(backend)  # No restriction on key types

# Example function to verify a signed SAML document
def verify_signed_saml_document(signed_document):
    try:
        # Parse the signed SAML document
        saml_response = saml.from_string(signed_document)
        
        # Verify the signature
        if verifier.verify(saml_response):
            print("Signature is valid.")
        else:
            print("Signature verification failed.")
    except Exception as e:
        print(f"An error occurred during verification: {e}")

# Example usage
signed_saml = "<Your Signed SAML Document Here>"
verify_signed_saml_document(signed_saml)