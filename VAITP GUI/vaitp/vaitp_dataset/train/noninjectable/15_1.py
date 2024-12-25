from PIL import Image

# Create an image object
try:
    img = Image.open("image.tif")
except FileNotFoundError:
    print("Error: image.tif not found. Please make sure the file exists.")
    exit()
except Exception as e:
    print(f"Error opening image: {e}")
    exit()

# Extract the tag data
if 270 in img.tag:
    tag_data = img.tag[270]  # 270 is the tag number for SAMPLESPERPIXEL
else:
    print("Error: Tag 270 not found in image.")
    exit()

# Create a malicious tag data that will cause a crash
malicious_tag_data = b"\x00" * 0x10000 # Reduced to avoid potential resource exhaustion or very slow processing

# Replace the original tag data with the malicious data. Important: we need to create a copy of the tags dict to avoid modifying the original one
img.tag = img.tag.copy()
img.tag[270] = malicious_tag_data


# Try to save the image, which might cause a crash or an error. Wrap in a try except to handle errors safely.
try:
    img.save("output.tif")
except Exception as e:
    print(f"Error saving image: {e}")

