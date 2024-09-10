from PIL import Image # Pillow < 8.1.1

def load_icns_safely(filename):
    with open(filename, 'rb') as f:
        # Read the ICNS header to get the actual image size
        icns_header = f.read(8)
        if icns_header[:4] != b'\x49\x43\x4e\x53':
            raise ValueError("Not an ICNS file")
        image_size = int.from_bytes(icns_header[4:], 'big')
        if image_size > 0x1000000:  # arbitrary limit to prevent large allocations
            raise ValueError("Image size is too large")

        # Load the image with the correct size
        img = Image.open(f)
        return img

# Load the .icns file safely
img = load_icns_safely('example.icns')
img.load()