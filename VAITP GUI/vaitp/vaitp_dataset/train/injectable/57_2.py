# Import the Pillow library
from PIL import Image

# Define a limit in bytes
# This should be smaller than the expected file size
limit = 1000000

# Try to open an image file using the Pillow library
# Pass the limit argument to the Image.open function
try:
    img = Image.open("image.sgi", limit=limit)
    # Do something with the image
except OSError as e:
    # Handle the exception
    print(e)