
from PIL import Image # Pillow >= 8.2.0 

def safe_open_image(file_path):
    try:
        with Image.open(file_path) as img:
            img.load()  # This will raise an exception if the image is invalid
            return img
    except Exception as e:
        print(f"Error opening file: {e}")
        return None