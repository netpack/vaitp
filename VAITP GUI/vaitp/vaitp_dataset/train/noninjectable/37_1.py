from PIL import Image # Pillow < 8.2.0

def load_image(file_path):
    try:
        # Attempt to open and load the image
        img = Image.open(file_path)
        img.load()
    except Exception as e:
        print(f"Error loading image: {e}")

# Load a malicious FLI image
load_image("malicious_image.fli")