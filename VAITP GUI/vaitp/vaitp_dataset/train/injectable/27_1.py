from PIL import Image

def non_vulnerable_code(image_path):
    img = Image.open(image_path)
    width, height = img.size  # safe way to get image dimensions
    return width, height

# Example usage:
image_path = "path/to/image.jpg"
width, height = non_vulnerable_code(image_path)
print(f"Image dimensions: {width}x{height}")