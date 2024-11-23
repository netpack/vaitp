import pypdf

def safe_pdf_processing(pdf_path):
    # Load the PDF file
    with open(pdf_path, "rb") as file:
        reader = pypdf.PdfReader(file)
        
        # Process each page safely
        for page in reader.pages:
            # Perform necessary operations on the page
            # This example simply extracts text, which is not vulnerable
            text = page.extract_text()
            print(text)

# Example usage
safe_pdf_processing("example.pdf")