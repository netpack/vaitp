# Import the PIL library
from PIL import Image

# Open a TIFF file using the Image.open() function
# This will trigger the buffer overflow and execute arbitrary code
image = Image.open("malicious.tiff")