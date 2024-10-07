from PIL import Image

# Create a black-and-white (B/W) RGB image
img = Image.new('RGB', (1, 1), (255, 255, 255))

# Save the image with a safe ZSIZE value
img.save('not_vulnerable_image.bmp', 'BMP', zsize=0)