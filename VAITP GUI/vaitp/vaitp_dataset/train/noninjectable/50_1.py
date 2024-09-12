from PIL import Image # Pillow < 8.3.2

def parse_image_string(image_string):
    Image.fromstring('RGB', (1, 1), image_string)

# Vulnerable code
parse_image_string('A' * 1000000)  # Maliciously crafted image string