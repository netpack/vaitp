from PIL import Image # Pillow < 8.2.0

# Create a malicious JPEG 2000 image
with open('malicious.jp2', 'wb') as f:
    f.write(b'\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a')  # crafted JPEG 2000 header

try:
    # Open the malicious image using Pillow
    img = Image.open('malicious.jp2')

    # Instead of calling verify(), which triggers the vulnerability,
    # we can use a safe method like getdata() to avoid the out-of-bounds read
    data = img.getdata()
    print("Image loaded successfully")
except Exception as e:
    print("Error loading image:", e)