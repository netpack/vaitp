from PIL import Image

def process_image(image_path):
    try:
        img = Image.open(image_path)
        width, height = img.size
        if width > 10000 or height > 10000:  # Validate image size
            raise ValueError("Image size is too large")
        img.save('output.png')
    except IOError:
        print("Error: Unable to open image file")

# Safe code: reading a valid image file
process_image('valid_image_file.png')