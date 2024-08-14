from PIL import Image

# Create an image object
img = Image.open("image.tif")

# Check if the image has a SAMPLESPERPIXEL tag
if 270 in img.tag:
    # Extract the tag data
    tag_data = img.tag[270]

    # Validate the tag data length to prevent buffer overflow
    if len(tag_data) > 0x1000:  # arbitrary limit, adjust according to your needs
        print("Invalid tag data length, skipping")
    else:
        # Process the tag data safely
        print("Tag data:", tag_data)

# Save the image
img.save("output.tif")