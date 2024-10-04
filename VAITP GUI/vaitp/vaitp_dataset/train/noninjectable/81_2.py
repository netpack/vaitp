# Import the Pillow library
from PIL import Image

# Open a malicious FLI file using the Image.open() function
# This will trigger the vulnerability and cause a denial of service
image = Image.open("malicious.fli")