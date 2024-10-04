# Import the Pillow library
from PIL import Image

# Open a malicious PSD image file
# This file has a large number of input layers
# This will trigger the vulnerability in the PSDImagePlugin.py module
# The open function will try to read each layer
# This will result in excessive CPU consumption
img = Image.open("malicious.psd")

# Try to display the image
# This will also trigger the vulnerability
img.show()