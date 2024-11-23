from M2Crypto import SSL

def verify_signature(verify_context, signature, data):
    # Properly check the return value from the verification function
    result = verify_context.verify(signature, data)
    if result != 1:
        raise Exception("Signature verification failed")
    return True

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

    try:
        if verify_signature(verify_context, signature, data):
            print("Signature is valid.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()