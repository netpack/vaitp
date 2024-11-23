from OpenSSL import crypto

def create_and_use_x509():
    # Create a new X509 certificate
    cert = crypto.X509()
    cert.set_version(2)  # Set version to X509v3
    cert.set_serial_number(1)  # Set a serial number

    # Simulate a scenario where the reference to the cert is lost
    # This could lead to use-after-free if the memory is reused
    del cert  # Explicitly delete the reference to the cert

    # Attempt to use the certificate after it has been deleted
    # This is where the vulnerability could be exploited
    try:
        print(cert)  # Accessing cert after deletion
    except NameError as e:
        print("Caught an error:", e)

# Run the function
create_and_use_x509()