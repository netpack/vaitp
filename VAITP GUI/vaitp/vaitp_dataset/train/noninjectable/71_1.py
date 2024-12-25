import struct
from PIL import Image

# Create a PCX file header with the shuffle flag set to TRUE
pcx_header = b'\x0A'  # Manufacturer
pcx_header += b'\x05'  # Version
pcx_header += b'\x01'  # Encoding (RLE)
pcx_header += b'\x08'  # Bits per pixel
pcx_header += struct.pack("<HH", 0, 0) # Xmin, Ymin
pcx_header += struct.pack("<HH", 63, 63) # Xmax, Ymax
pcx_header += struct.pack("<HH", 640, 480) # HDPI, VDPI
pcx_header += b'\x00' * 48  # Color map
pcx_header += b'\x00'  # Reserved
pcx_header += b'\x01'  # Number of color planes
pcx_header += struct.pack("<H", 64)  # Bytes per line
pcx_header += struct.pack("<H", 0x01)  # Palette type
pcx_header += struct.pack("<H", 120) # horizontal res
pcx_header += struct.pack("<H", 120)  #vertical res
pcx_header += b'\x00' * 54 # filler

# Create a simple 8x8 image data (black) for testing
image_data = b''
for _ in range(64): # 64 = 8 * 8
    image_data += b'\x00\x00'


# Create a PCX file with the crafted header
with open("crafted_pcx.pcx", "wb") as f:
    f.write(pcx_header)
    f.write(image_data)


print("Crafted PCX file created: crafted_pcx.pcx")

# Open the crafted PCX file using Pillow
try:
    img = Image.open("crafted_pcx.pcx")
    print("Pillow opened the crafted PCX file successfully.")

    # Perform an operation on the image (e.g., resize)
    img = img.resize((100, 100))
    img.save("resized_pcx.pcx") # Saving the resized version
    print("Resized and saved the image as resized_pcx.pcx")


    # Close the image
    img.close()
except Exception as e:
    print("Error: Pillow failed to open or process the crafted PCX file.")
    print(f"Error message: {e}")