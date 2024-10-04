# Import the Pillow module
from PIL import Image

# Define a malicious SGI image file
# This file has a crafted header
# The header will cause an out-of-bounds read
image_file = "evil.sgi"

# Open the image file with Pillow
# This will trigger the vulnerability in the Pillow module
# The Image.open function will read beyond the allocated buffer
image = Image.open(image_file)