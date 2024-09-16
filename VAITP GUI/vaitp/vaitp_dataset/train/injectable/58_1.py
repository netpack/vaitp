import io
from PIL import Image

# Create a crafted YCbCr file (same as before)
with open("crafted_tiff.tif", "wb") as f:
    f.write(b"\x49\x49\x2A\x00\x10\x00\x00\x00\x11\x00\x12\x00\x13\x00\x14\x00\x15\x00\x16\x00\x17\x00\x18\x00\x19\x00\x1A\x00")

# Open the crafted file using Pillow, but with a safe configuration
with Image.open("crafted_tiff.tif") as img:
    # Disable RGBA mode to prevent the vulnerability
    img.mode = 'RGB'
    # Load the image with the safe configuration
    img.load()