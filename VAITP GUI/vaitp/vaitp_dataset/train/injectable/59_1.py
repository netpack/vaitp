from PIL import Image

def process_pcx_file(file_path):
    with open(file_path, 'rb') as f:
        pcx_data = f.read()
    try:
        img = Image.open(file_path)  # use Image.open instead of Image.frombytes
        img.verify()  # verify the image data to prevent buffer over-read
        img.show()
    except IOError:
        print("Error: Unable to load image")

# Example usage:
process_pcx_file('crafted_pcx_file.pcx')