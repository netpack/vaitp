from PIL import Image

def parse_sgi_image_safe(file_path):
    try:
        with open(file_path, 'rb') as f:
            image_data = f.read(12)  # Read only the header (first 12 bytes)
            width = int.from_bytes(image_data[0:2], byteorder='big')
            height = int.from_bytes(image_data[2:4], byteorder='big')
            if width <= 0 or height <= 0:
                raise ValueError("Invalid image dimensions")
            img = Image.frombytes('L', (width, height), image_data[8:], decoder_name='sgi_rle')
            return img
    except ValueError as e:
        print(f"Error parsing SGI image: {e}")
        return None

# Example usage:
sgi_image_path = 'example.sgi'
img = parse_sgi_image_safe(sgi_image_path)
if img:
    print("Image loaded successfully")
else:
    print("Failed to load image")