from PIL import Image

# Create an image object
img = Image.open('image.jpg')

# Trigger the vulnerability by accessing an out-of-bounds pixel
pixel_data = img.load()
pixel_data[1000000, 1000000]  # This will cause an out-of-bounds read