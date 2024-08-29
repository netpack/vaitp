from PIL import Image

def vulnerable_code(image_path):
    img = Image.open(image_path)
    path = img.getbbox()  # vulnerable call to path_getbbox
    return path

# Example usage:
image_path = "path/to/image.jpg"
vulnerable_code(image_path)