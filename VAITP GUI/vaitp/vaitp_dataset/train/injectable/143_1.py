# Import the Pillow library
from PIL import Image

# Open a malicious TIFF file
img = Image.open("malicious.tiff")

# Try to load the image data and handle the exception
try:
    img.load()
except IOError:
    print("Buffer overflow detected, aborting.")