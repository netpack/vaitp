# Import the Pillow library
from PIL import Image

# Open a malicious TIFF file
img = Image.open("malicious.tiff")

# Try to load the image data
img.load()