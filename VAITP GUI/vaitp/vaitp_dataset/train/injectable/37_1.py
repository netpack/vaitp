from PIL import Image # Pillow < 8.2.0

# Open a malicious FLI image file (but not exploitable)
img = Image.open("malicious.fli")

# Convert the image to a safe format (e.g., JPEG)
img.save("safe_image.jpg", "JPEG")

# Display the safe image
img.show()