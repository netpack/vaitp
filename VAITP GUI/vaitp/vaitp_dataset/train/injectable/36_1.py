from PIL import Image # Pillow < 8.3.2
import imghdr
import os

def open_image(file_path):
    # Check if the file is an EPS file
    if os.path.splitext(file_path)[1].lower() == '.eps':
        print("Error: EPS files are not supported")
        return

    # Check if the file is a valid image
    image_type = imghdr.what(file_path)
    if image_type not in ['jpeg', 'png', 'gif', 'bmp', 'tiff']:
        print("Error: Invalid image file")
        return

    try:
        # Open the image file using Pillow's Image.open() function
        with Image.open(file_path) as img:
            # Perform some operation on the image
            img.verify()
    except Exception as e:
        print(f"Error opening image: {e}")

# Example usage:
# Replace 'image_file.jpg' with the path to a valid image file
open_image('image_file.jpg')

# Attempt to open the malicious EPS file
open_image('malicious_eps_file.eps')