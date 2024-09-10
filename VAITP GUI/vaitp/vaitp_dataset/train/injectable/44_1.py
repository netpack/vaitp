from PIL import Image # Pillow < 8.1.1
import io

def process_pdf(file_path):
    with open(file_path, 'rb') as f:
        # Read the PDF file into a bytes buffer
        pdf_bytes = f.read()
        
        # Create a BytesIO object from the bytes buffer
        buffer = io.BytesIO(pdf_bytes)
        
        # Open the PDF file using Pillow's Image.open method,
        # but with the `formats` parameter set to ['PDF']
        img = Image.open(buffer, formats=['PDF'])
        
        # Perform some operations on the image
        img.load()

# Example usage:
process_pdf('malicious_pdf_file.pdf')