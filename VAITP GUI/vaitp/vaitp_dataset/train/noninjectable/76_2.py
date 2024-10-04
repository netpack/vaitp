# Import the PIL library
from PIL import Image

# Open a FLI file using the Image.open() function
# This will trigger the buffer overflow and execute arbitrary code
image = Image.open("malicious.fli")