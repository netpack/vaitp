from imageop import crop
from PIL import Image

# Create an image with dimensions that could trigger the vulnerability
image = Image.new('RGB', (1000, 1000))

# Check if the crop coordinates are within valid ranges
crop_coords = (0, 0, 1001, 1001)
if (crop_coords[2] <= image.size[0] and crop_coords[3] <= image.size[1]):
    # Crop the image with dimensions that do not trigger the vulnerability
    cropped_image = crop(image, crop_coords)
else:
    print("Error: Crop coordinates are out of bounds")