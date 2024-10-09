from imageop import crop
from PIL import Image

# Create an image with dimensions that do not trigger the vulnerability
image = Image.new('RGB', (1000, 1000))

# Crop the image with dimensions that do not trigger the vulnerability
cropped_image = crop(image, (0, 0, 1000, 1000))