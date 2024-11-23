from saml2 import saml, sigver

# Load your SAML configuration
# This is a representation of the vulnerable code before the fix
def process_saml_response(saml_response):
    # Parse the SAML response
    response = saml.Response(saml_response)

    # Attempt to verify the signature without proper validation
    try:
        # This method does not validate the SAML document against an XML schema
        sigver.verify_signature(response)
    except sigver.SignatureError as e:
        print("Signature verification failed:", e)
        return False

    # If the signature is valid, process the response
    return True

# Example usage
saml_response = "<Your SAML Response Here>"
is_valid = process_saml_response(saml_response)
print("Is the SAML response valid?", is_valid)