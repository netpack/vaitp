# Import the Pillow library
from PIL import Image

# Open a malicious image file
# This image file has a crafted SGI header
# It can trigger the out-of-bounds read in J2kDecode.c
img = Image.open("malicious.sgi")

# Try to load the image data using the Pillow library
# This will cause a segmentation fault due to the vulnerability
img.load()