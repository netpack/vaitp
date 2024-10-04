from PIL import Image

def process_image(image_path):
    with open(image_path, 'rb') as f:
        image_data = f.read()
    img = Image.frombytes('RGB', (1000000, 1000000), image_data)  # Large image size
    img.save('output.png')

# Vulnerable code: reading a specially crafted invalid image file
process_image('crafted_image_file.png')