from PIL import Image

def safely_open_image(image_path):
    try:
        # Open the image with Pillow, using the `verify=True` parameter to validate the image
        img = Image.open(image_path, verify=True)
        
        # Check if the image is valid and not corrupted
        if not img.verify():
            raise ValueError("Invalid or corrupted image")
        
        # Process the image (e.g., resize, convert, etc.)
        img = img.resize((300, 300))  # Example: resize the image
        
        return img
    except (IOError, Image.DecompressionBombError, ValueError) as e:
        print(f"Error opening image: {e}")
        return None

# Test the function with a malicious input image
malicious_image_path = "malicious_image.tga"
safely_open_image(malicious_image_path)