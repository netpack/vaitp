import struct
from PIL import Image

# Create a PCX file header with the shuffle flag set to FALSE and valid dimensions
pcx_header = b'\x0A'  # Manufacturer (ZSoft)
pcx_header += b'\x05'  # Version number (PC Paintbrush 2.5)
pcx_header += b'\x01'  # Encoding (RLE)
pcx_header += b'\x08'  # Bits per pixel
pcx_header += struct.pack('<h', 0)  # xmin
pcx_header += struct.pack('<h', 0)  # ymin
pcx_header += struct.pack('<h', 15)  # xmax (16 pixels wide)
pcx_header += struct.pack('<h', 15)  # ymax (16 pixels high)
pcx_header += struct.pack('<h', 300) # Horizontal DPI
pcx_header += struct.pack('<h', 300) # Vertical DPI
pcx_header += b'\x00' * 48 # Color Map
pcx_header += b'\x00'  # Reserved
pcx_header += b'\x01'  # Number of planes
pcx_header += struct.pack('<h', 16)  # Bytes per line
pcx_header += struct.pack('<h', 2) # Palette type
pcx_header += struct.pack('<h', 0) # Horizontal screen size
pcx_header += struct.pack('<h', 0) # Vertical screen size
pcx_header += b'\x00' * 54  # Reserved

# Create dummy pixel data (16x16 monochrome)
pixel_data = b''
for _ in range(16):
    pixel_data += b'\xaa'  # Example monochrome data.
    
# Create dummy palette data (grayscale)
palette_data = b''
for i in range(256):
     palette_data += bytes([i,i,i])

# Create a PCX file with the crafted header and valid pixel and palette data
with open("patched_pcx.pcx", "wb") as f:
    f.write(pcx_header)
    f.write(pixel_data)
    f.write(b'\x0C\xC0') # End of pixel data marker
    f.write(b'\x0C') #Start of Palette Data marker
    f.write(palette_data)

print("Patched PCX file created: patched_pcx.pcx")

# Open the patched PCX file using Pillow with error handling
try:
    img = Image.open("patched_pcx.pcx")
    print("Pillow opened the patched PCX file successfully.")

    # Check if the image is valid before performing operations
    if img.mode == 'P' and img.palette:
        # Perform an operation on the image (e.g., resize)
        img = img.resize((100, 100))
        img.save("resized_patched_pcx.png") # Save resized image in PNG format
        print("Resized and saved the patched PCX file.")
    else:
        print("Image is not valid or does not have a palette.")

    # Close the image
    img.close()
except Exception as e:
    print("Error: Pillow failed to open or process the patched PCX file.")
    print(f"Error message: {e}")
