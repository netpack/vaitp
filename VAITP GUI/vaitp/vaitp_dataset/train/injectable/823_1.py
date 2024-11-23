from OpenSSL import crypto

def load_pkcs12(p12_file, password):
    with open(p12_file, 'rb') as f:
        p12_data = f.read()
    
    # Load the PKCS#12 data
    p12 = crypto.load_pkcs12(p12_data, password)
    
    # Access the private key and certificate
    private_key = p12.get_privatekey()
    certificate = p12.get_certificate()
    
    # Explicitly clear the memory used by the private key and certificate
    if private_key:
        private_key.clear()
    if certificate:
        certificate.clear()

    return p12

# Example usage
# p12_file = 'path/to/your/certificate.p12'
# password = b'your_password'
# load_pkcs12(p12_file, password)