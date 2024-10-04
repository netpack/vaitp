# Import the Pillow library
from PIL import Image

# Open a malicious image file
# This image file has a crafted TIFF header
# It can trigger the out-of-bounds read in TiffDecode.c
img = Image.open("malicious.tiff")

# Try to load the image data using the Pillow library
# This will cause a segmentation fault due to the vulnerability
img.load()