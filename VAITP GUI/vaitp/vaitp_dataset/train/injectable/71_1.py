import struct
from PIL import Image

# Create a PCX file header with the shuffle flag set to TRUE
pcx_header = b'\xC5\x50\x43\x58'  # PCX file signature
pcx_header += b'\x01'  # Version number
pcx_header += b'\x01'  # Encoding (RLE)
pcx_header += b'\x10\x00'  # Bytes per line
pcx_header += b'\x10\x00'  # Palette type
pcx_header += b'\x01\x00'  # Shuffle flag (TRUE)
pcx_header += b'\x00\x00'  # Reserved
pcx_header += b'\x00\x00'  # Number of planes
pcx_header += b'\x10\x00'  # Bytes per line (again)
pcx_header += b'\x10\x00'  # Palette size

# Create a PCX file with the crafted header
with open("crafted_pcx.pcx", "wb") as f:
    f.write(pcx_header)

print("Crafted PCX file created: crafted_pcx.pcx")

# Open the crafted PCX file using Pillow with error handling
try:
    img = Image.open("crafted_pcx.pcx")
    print("Pillow opened the crafted PCX file successfully.")

    # Check if the image is valid before performing operations
    if img.mode == 'P' and img.palette:
        # Perform an operation on the image (e.g., resize)
        img.resize((100, 100))
    else:
        print("Image is not valid or does not have a palette.")

    # Close the image
    img.close()
except Exception as e:
    print("Error: Pillow failed to open or process the crafted PCX file.")
    print(f"Error message: {e}")