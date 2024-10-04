# Import the Pillow library
from PIL import Image

# Create a temporary file name with spaces
temp_file = "temp file.jpg"

# Open an image file
img = Image.open("image.jpg")

# Save the image as a JPEG file with the temporary file name
# This will create a temporary file with spaces in the name
img.save(temp_file, "JPEG")

# Delete the temporary file using the remove method of the Pillow library
# This will fail to delete the file because of the spaces in the name
# Instead, it will delete the files "temp", "file.jpg", and any other file that matches the pattern "temp*"
Image.core.remove(temp_file)