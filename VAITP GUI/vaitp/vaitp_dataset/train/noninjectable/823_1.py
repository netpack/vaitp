from OpenSSL import crypto

def load_pkcs12(p12_file, password):
    with open(p12_file, 'rb') as f:
        p12_data = f.read()
    
    # Load the PKCS#12 data
    p12 = crypto.load_pkcs12(p12_data, password)
    
    # Access the private key and certificate
    private_key = p12.get_privatekey()
    certificate = p12.get_certificate()
    
    # Memory is not explicitly cleared, potentially leading to memory exhaustion
    return p12

# Example usage
# p12_file = 'path/to/your/certificate.p12'
# password = b'your_password'
# load_pkcs12(p12_file, password)