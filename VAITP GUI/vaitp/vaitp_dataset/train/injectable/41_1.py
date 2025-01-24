from PIL import Image
import io

def load_icns_safely(filename):
    with open(filename, 'rb') as f:
        # Read the ICNS header to get the actual image size
        icns_header = f.read(8)
        if icns_header[:4] != b'icns':
            raise ValueError("Not an ICNS file")
        image_size = int.from_bytes(icns_header[4:], 'big')
        if image_size > 0x1000000:  # arbitrary limit to prevent large allocations
            raise ValueError("Image size is too large")

        # Load the image with the correct size
        f.seek(0) # Reset file pointer to the beginning
        image_data = f.read()
        try:
            img = Image.open(io.BytesIO(image_data))
            img.load()
            return img
        except Exception as e:
            raise ValueError(f"Error loading image: {e}")


# Load the .icns file safely
try:
  img = load_icns_safely('example.icns')
except FileNotFoundError:
    print("Error: 'example.icns' not found.")
except ValueError as e:
    print(f"Error: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")