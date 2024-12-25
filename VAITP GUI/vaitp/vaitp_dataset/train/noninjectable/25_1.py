from PIL import Image
import os

def process_image(image_path):
    # Create a temporary file with a space in the name
    temp_file = "temp_file.png"
    image = Image.open(image_path)
    image.save(temp_file)
    # Do some processing on the temporary file
    # ...
    # Delete the temporary file
    os.remove(temp_file)

# Example usage:
image_path = "example.jpg"
# Check if example.jpg exists in current directory
if os.path.exists(image_path):
    process_image(image_path)
else:
    print(f"Error: {image_path} not found")