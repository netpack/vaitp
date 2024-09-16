from PIL import Image

def load_image(filename):
    image = Image.open(filename)

    # Check if the image size exceeds a reasonable limit
    max_size = 10000000
    if image.size[0] > max_size or image.size[1] > max_size:
        raise ValueError("Image size exceeds maximum allowed size")

    return image

# Load the image and handle potential exceptions
try:
    image = load_image("image.jpg")
    print("Image loaded successfully!")
except ValueError as e:
    print(f"Error loading image: {e}")