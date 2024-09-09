from PIL import Image

def vulnerable_code(image_path):
    try:
        # Open the image file without any validation
        img = Image.open(image_path)
        
        # Load the image data without any checks
        img.load()
        
        # Process the image data
        print("Image loaded successfully")
        
    except Exception as e:
        print(f"Error: {e}")

# Example usage
image_path = "example.psd"  # Replace with a PSD file
vulnerable_code(image_path)