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

# Function to validate SSH certificate
def validate_ssh_certificate(cert):
    # Check for critical options
    if "force-command" in cert["critical_options"]:
        raise ValueError("Critical option 'force-command' is not allowed for security reasons.")
    print("SSH certificate is valid.")

# Simulate handling of the SSH certificate with validation
def handle_ssh_certificate(cert):
    try:
        validate_ssh_certificate(cert)
        print("Handling SSH certificate...")
        print(f"Key: {cert['key']}")
    except ValueError as e:
        print(f"Validation Error: {e}")

# Call the function with the certificate
handle_ssh_certificate(ssh_cert)