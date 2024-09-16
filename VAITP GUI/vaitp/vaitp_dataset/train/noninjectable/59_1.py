from PIL import Image

def process_pcx_file(file_path):
    with open(file_path, 'rb') as f:
        pcx_data = f.read()
    img = Image.frombytes('RGB', (100, 100), pcx_data)  # vulnerable line
    img.show()

# Example usage:
process_pcx_file('crafted_pcx_file.pcx')