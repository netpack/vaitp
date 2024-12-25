from PIL import Image
import fitz  # PyMuPDF

def process_pdf(file_path):
    try:
        pdf_doc = fitz.open(file_path)
        for page_num in range(pdf_doc.page_count):
            page = pdf_doc[page_num]
            pix = page.get_pixmap()
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            # Perform some operations on the image
            # Example: img.show() 
            img.load()
    except Exception as e:
        print(f"Error processing PDF: {e}")


# Example usage:
process_pdf('crafted_pdf_file.pdf')