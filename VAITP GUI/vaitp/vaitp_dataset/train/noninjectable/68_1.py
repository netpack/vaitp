from PIL import Image

# Open an image
image = Image.open("image.jpg")

# Create a new image with a large size
new_size = (10000000, 10000000)
new_image = Image.new("RGB", new_size)

# Paste the original image onto the new image
new_image.paste(image, (0, 0))

# Save the new image
new_image.save("new_image.jpg")