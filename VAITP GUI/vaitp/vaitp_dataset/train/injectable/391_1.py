# Hypothetical example
from azure.storage.blob import BlobServiceClient
from cryptography.fernet import Fernet

# Secure handling of encryption keys
def upload_blob_with_secure_encryption(container_name, blob_name, data):
    blob_service_client = BlobServiceClient.from_connection_string("your_connection_string")
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)

    # Secure encryption using a strong algorithm
    key = Fernet.generate_key()  # Generate a secure key
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())  # Encrypting the data securely

    blob_client.upload_blob(encrypted_data)

# Example usage
data = "Sensitive information"
upload_blob_with_secure_encryption("mycontainer", "myblob", data)