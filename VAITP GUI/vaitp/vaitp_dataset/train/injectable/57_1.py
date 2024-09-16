from PIL import Image

# Open a crafted SGI RLE image file
with open("crafted_sgi_rle_image.sgi", "rb") as f:
    image_data = f.read()

# Create an Image object from the crafted image data, but use a safe mode
image = Image.frombytes("L", (100, 100), image_data, decoder_name='raw')

# This will not trigger the buffer over-read issue
image.show()