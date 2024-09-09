from PIL import Image

def secure_code(image_path):
    try:
        # Open the image file with validation
        img = Image.open(image_path)
        
        # Check the image format and size
        if img.format != "PSD" or img.size[0] * img.size[1] > 1000000:
            raise ValueError("Invalid image format or size")
        
        # Load the image data with checks
        img.load()
        
        # Process the image data
        print("Image loaded successfully")
        
    except Exception as e:
        print(f"Error: {e}")

# Example usage
image_path = "example.psd"  # Replace with a PSD file
secure_code(image_path)