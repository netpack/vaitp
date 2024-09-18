from PIL import Image

# Create an image object
img = Image.open('image.jpg')

# Get the image dimensions
width, height = img.size

# Trigger the vulnerability by accessing an out-of-bounds pixel, but with bounds checking
pixel_data = img.load()
try:
    pixel_data[1000000, 1000000]  # This will cause an out-of-bounds read
except IndexError:
    print("Out-of-bounds read detected!")