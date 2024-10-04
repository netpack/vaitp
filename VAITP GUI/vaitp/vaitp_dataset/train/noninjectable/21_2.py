# Import the Pillow library
from PIL import Image

# Open a malicious TGA image file
# This file has a negative height value in the header
# This will trigger the heap buffer overflow in the TgaRleDecode function
img = Image.open("malicious.tga")

# Try to save the image as a PNG file
# This will cause the program to crash or execute arbitrary code
img.save("output.png")