from PIL import Image

# Open a crafted SGI RLE image file
with open("crafted_sgi_rle_image.sgi", "rb") as f:
    image_data = f.read()

# Create an Image object from the crafted image data
image = Image.frombytes("L", (100, 100), image_data)

# This will trigger the buffer over-read issue
image.show()