from PIL import Image

def process_pcx_file(file_path):
    try:
        img = Image.open(file_path)
        img.verify()
        img.show()
    except IOError:
        print("Error: Unable to load image")

# Example usage:
process_pcx_file('crafted_pcx_file.pcx')