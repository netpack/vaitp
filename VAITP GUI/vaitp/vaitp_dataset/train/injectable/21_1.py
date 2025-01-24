
from PIL import Image

def safely_open_image(image_path):
    try:
        # Open the image with Pillow, using the `verify=True` parameter to validate the image
        img = Image.open(image_path, mode='r')
        with open(image_path, 'rb') as f:
            data = f.read()
        
        # Check if the image is valid and not corrupted
        if not img.verify():
            raise Image.DecompressionBombError
        
        # Process the image (e.g., resize, convert, etc.)
        img = img.resize((300, 300))  # Example: resize the image
        
        return img
    except (IOError, Image.DecompressionBombError, ValueError) as e:
        print(f"Error opening image: {e}")
        return None