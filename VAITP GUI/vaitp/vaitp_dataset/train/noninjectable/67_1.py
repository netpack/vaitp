from PIL import Image

def parse_sgi_image(file_path):
    with open(file_path, 'rb') as f:
        image_data = f.read()
    img = Image.frombytes('L', (image_data[0] << 16) + image_data[1], image_data[2:], decoder_name='sgi_rle')
    return img

# Example usage:
sgi_image_path = 'example.sgi'
parse_sgi_image(sgi_image_path)