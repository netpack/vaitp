from PIL import Image

# Open the SGI image file using Pillow, but with a safe load method
try:
    img = Image.open("image.sgi", formats=["SGI"])
except Exception as e:
    print(f"Error opening image: {e}")
    exit()

# Load the image data, but with a safe load method
try:
    img.load()
except Exception as e:
    print(f"Error loading image data: {e}")
    exit()


# Now you can safely use the image data
print(img.size)