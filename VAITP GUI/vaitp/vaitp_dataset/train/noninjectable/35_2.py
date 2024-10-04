# Import the Pillow library
from PIL import Image

# Open a malicious BLP image file
# This file has a large number of mipmaps
# This will trigger the vulnerability in the BlpImagePlugin.py module
# The open function will try to read each mipmap
# This will result in excessive CPU consumption
img = Image.open("malicious.blp")

# Try to display the image
# This will also trigger the vulnerability
img.show()