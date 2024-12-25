# Import the Pillow library
from PIL import Image
import os

# Create a temporary file name with spaces
temp_file = "temp file.jpg"

# Open an image file
img = Image.open("image.jpg")

# Save the image as a JPEG file with the temporary file name
# This will create a temporary file with spaces in the name
img.save(temp_file, "JPEG")

# Delete the temporary file using the os.remove method
# This will correctly delete the file with spaces in the name
os.remove(temp_file)