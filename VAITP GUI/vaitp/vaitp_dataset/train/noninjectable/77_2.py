# Import the PIL library
from PIL import Image

# Open a PCX file using the Image.open() function
# This will trigger the buffer overflow and execute arbitrary code
image = Image.open("malicious.pcx")