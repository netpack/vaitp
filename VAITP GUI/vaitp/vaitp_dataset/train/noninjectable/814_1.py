from aws_encryption_sdk import encrypt, decrypt
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider

# Initialize the KMS master key provider
kms_key_provider = KMSMasterKeyProvider(key_ids=['your-kms-key-id'])

# Function to encrypt data (vulnerable implementation)
def vulnerable_encrypt(plaintext):
    # Encrypt the plaintext using AES-GCM (vulnerable to CVE-2020-8897)
    ciphertext, encryptor_header = encrypt(
        source=plaintext,
        key_provider=kms_key_provider
    )
    return ciphertext

# Function to decrypt data
def decrypt_data(ciphertext):
    # Decrypt the ciphertext (may yield different plaintexts for the same ciphertext)
    plaintext, decryptor_header = decrypt(
        source=ciphertext
    )
    return plaintext

# Example usage
if __name__ == "__main__":
    # Original plaintext
    plaintext = b"Sensitive data that needs encryption"

    # Encrypt the plaintext (vulnerable)
    encrypted_data = vulnerable_encrypt(plaintext)
    print("Encrypted data:", encrypted_data)

    # Decrypt the ciphertext (may result in multiple possible plaintexts)
    decrypted_data = decrypt_data(encrypted_data)
    print("Decrypted data:", decrypted_data)