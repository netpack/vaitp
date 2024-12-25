from aws_encryption_sdk import EncryptedDataKey, encrypt, decrypt
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider

# Initialize the KMS master key provider
kms_key_provider = KMSMasterKeyProvider(key_ids=['your-kms-key-id'])

# Function to encrypt data securely
def secure_encrypt(plaintext):
    # Encrypt the plaintext
    ciphertext, encryptor_header = encrypt(
        source=plaintext,
        key_provider=kms_key_provider
    )
    return ciphertext

# Function to decrypt data securely
def secure_decrypt(ciphertext):
    # Decrypt the ciphertext
    plaintext, decryptor_header = decrypt(
        source=ciphertext,
        key_provider=kms_key_provider
    )
    return plaintext

# Example usage
if __name__ == "__main__":
    # Original plaintext
    plaintext = b"Sensitive data that needs encryption"

    # Encrypt the plaintext
    encrypted_data = secure_encrypt(plaintext)
    print("Encrypted data:", encrypted_data)

    # Decrypt the ciphertext
    decrypted_data = secure_decrypt(encrypted_data)
    print("Decrypted data:", decrypted_data)