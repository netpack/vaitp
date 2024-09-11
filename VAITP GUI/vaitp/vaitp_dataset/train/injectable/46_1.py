from PIL import Image # Pillow < 8.1.1

# Create a TIFF image with a maliciously crafted IFD (Image File Directory)
ifd = bytearray(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20')
ifd += b'\x00\x00\x00\x00'  # Offset to the next IFD (negative offset)
ifd += b'\x00\x00\x00\x10'  # Size of the next IFD (invalid size)

# Create a TIFF image from the malicious IFD, but use the `decode` parameter to disable decoding
image = Image.frombytes('I;16', (100, 100), ifd, decode=False)

# The image is not decoded, so the vulnerability is not triggered
print("Image loaded successfully, but not decoded")