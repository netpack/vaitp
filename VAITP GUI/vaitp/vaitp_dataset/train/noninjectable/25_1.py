from PIL import Image, os

def process_image(image_path):
    # Create a temporary file with a space in the name
    temp_file = "temp file.png"
    image = Image.open(image_path)
    image.save(temp_file)
    # Do some processing on the temporary file
    # ...
    # Delete the temporary file
    os.remove(temp_file)

# Example usage:
image_path = "example.jpg"
process_image(image_path)