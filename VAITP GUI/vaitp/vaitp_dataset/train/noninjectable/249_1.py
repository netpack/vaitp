from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate a new RSA key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Serialize the private key
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL
)

# Create a dummy SSH certificate with critical options
ssh_cert = {
    "key": private_pem,
    "critical_options": {
        "force-command": "echo 'This is a critical command'"
    }
}

# Simulate the mishandling of the SSH certificate
def handle_ssh_certificate(cert):
    # This function should validate the certificate properly
    # However, it does not check for critical options correctly
    print("Handling SSH certificate without proper validation...")
    print(f"Key: {cert['key']}")
    print(f"Critical Options: {cert['critical_options']}")

# Call the function with the vulnerable certificate
handle_ssh_certificate(ssh_cert)