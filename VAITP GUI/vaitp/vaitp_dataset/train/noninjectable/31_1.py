from PIL import Image # Assumes Pillow < 8.3.2

def convert_image(image_path):
    image = Image.open(image_path)
    image.convert('RGB')  # Vulnerable to buffer overflow (the vulnerability is in the C code)
    return image

# Example usage:
image_path = 'path/to/image.jpg'
converted_image = convert_image(image_path)