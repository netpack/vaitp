# Import the Pillow library
from PIL import Image

# Open a malicious PDF file
# This file has a large number of nested dictionaries
# This will trigger the vulnerability in the PdfParser.py module
# The decode_pdf function will use a regular expression that is prone to catastrophic backtracking
# This will result in excessive CPU consumption
img = Image.open("malicious.pdf")

# Try to display the image
# This will also trigger the vulnerability
img.show()