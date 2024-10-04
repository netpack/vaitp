# Import the Pillow library
from PIL import Image

# Open a malicious GIF image file
# This file has highly compressed data that expands to over 4 GB
img = Image.open("malicious.gif")

# Try to load the image data
# This will trigger the vulnerability in the GifImagePlugin.py module
# The load function will try to allocate a huge buffer in memory
# This will result in a memory allocation error and a denial of service
img.load()