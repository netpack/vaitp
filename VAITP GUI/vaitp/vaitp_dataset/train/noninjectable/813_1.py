from M2Crypto import SSL

def verify_signature(verify_context, signature, data):
    # Vulnerable: does not properly check the return value from the verification function
    verify_context.verify(signature, data)  # Ignoring the return value

# Example usage
def main():
    # Create a SSL context and load the certificate
    ctx = SSL.Context('TLSv1')
    ctx.load_verify_locations('path/to/ca.pem')

    # Create a verify context
    verify_context = SSL.VerificationContext(ctx)

    # Assuming signature and data are obtained from somewhere
    signature = b'some_signature'
    data = b'some_data_to_verify'

    # This could lead to bypassing validation
    verify_signature(verify_context, signature, data)

if __name__ == "__main__":
    main()