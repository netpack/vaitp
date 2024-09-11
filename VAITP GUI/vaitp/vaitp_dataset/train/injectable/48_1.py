from PIL import Image # Pillow < 8.2.0

def non_vulnerable_function(image_data):
    # Validate the image data before creating an image object
    if len(image_data) < 100 * 100:  # Check if the image data is within expected bounds
        img = Image.frombytes('L', (100, 100), image_data)
        img.show()
    else:
        print("Invalid image data")

# Create some image data that is within expected bounds
valid_image_data = b'\x00' * 10000  # Create a buffer of zeros within expected bounds

# Call the non-vulnerable function with the valid image data
non_vulnerable_function(valid_image_data)