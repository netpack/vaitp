from PIL import Image # Pillow < 8.1.1

def process_pdf(file_path):
    with open(file_path, 'rb') as f:
        img = Image.open(f)
        # Perform some operations on the image
        img.load()

# Example usage:
process_pdf('crafted_pdf_file.pdf')