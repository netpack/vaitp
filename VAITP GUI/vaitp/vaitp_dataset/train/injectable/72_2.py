from PIL import Image

# Create an image object
img = Image.open('image.jpg')

# Get the image dimensions
width, height = img.size

# Trigger the vulnerability by accessing an out-of-bounds pixel, but with bounds checking
pixel_data = img.load()
if 1000000 < width and 1000000 < height:
    pixel_data[1000000, 1000000]  # This will not cause an out-of-bounds read
else:
    print("Out-of-bounds read detected!")