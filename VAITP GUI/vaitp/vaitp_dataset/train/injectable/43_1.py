from PIL import Image # Pillow < 8.1.1

# Open the SGI image file using Pillow, but with a safe load method
img = Image.open("image.sgi", formats=["SGI"])

# Load the image data, but with a safe load method
img.load()

# Now you can safely use the image data
print(img.size)