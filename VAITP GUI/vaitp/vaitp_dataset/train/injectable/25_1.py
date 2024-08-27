from PIL import Image
import os
import tempfile

def process_image(image_path):
    # Create a temporary file with a unique name
    with tempfile.NamedTemporaryFile(suffix=".png") as temp_file:
        image = Image.open(image_path)
        image.save(temp_file.name)
        # Do some processing on the temporary file
        # ...
        # The temporary file will be automatically deleted when it goes out of scope

# Example usage:
image_path = "example.jpg"
process_image(image_path)