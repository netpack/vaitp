
from PIL import Image

def process_pcx_file(file_path):
    try:
        img = Image.open(file_path)
        img.verify()
        # Verify the size of the image to prevent excessive memory usage
        if img.width * img.height > 1000000:
            raise ValueError("Image size is too large")
        img.show()
    except (IOError, ValueError) as e:
        print(f"Error: {e}")