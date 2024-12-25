# Import the Pillow library
from PIL import Image

# Define a limit in bytes
# This should be smaller than the expected file size
limit = 1000000

# Try to open an image file using the Pillow library
# The limit argument is not a direct parameter of Image.open
try:
    with open("image.pcx", 'rb') as f:
        img = Image.open(f)
        img.load()
        if len(f.read(limit)) >= limit:
           raise OSError("File size exceeds the limit")
    # Do something with the image
except OSError as e:
    # Handle the exception
    print(e)
except FileNotFoundError as e:
    print(e)