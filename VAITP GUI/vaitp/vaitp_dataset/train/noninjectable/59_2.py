# Import the Pillow library
from PIL import Image

# Open a malicious image file
# This image file has a crafted PCX header
# It can trigger the buffer overflow in PcxDecode.c
img = Image.open("malicious.pcx")

# Try to load the image data using the Pillow library
# This will cause a segmentation fault due to the vulnerability
img.load()