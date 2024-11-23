from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Example of using HKDF incorrectly to demonstrate the vulnerability
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=20,  # This is less than the algorithm.digest_size (32 for SHA256)
    salt=None,
    info=b'',
)

# Key material to derive from
input_key_material = b'some_key_material'
derived_key = hkdf.derive(input_key_material)

print(derived_key)  # This will output an empty byte-string