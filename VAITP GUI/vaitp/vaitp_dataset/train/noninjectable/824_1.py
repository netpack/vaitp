import pypdf

def vulnerable_pdf_processing(pdf_path):
    # Load the PDF file
    with open(pdf_path, "rb") as file:
        reader = pypdf.PdfReader(file)
        
        # Process pages in a way that can lead to quadratic runtime
        for i in range(len(reader.pages)):
            for j in range(len(reader.pages)):
                # This nested loop can cause performance issues
                # Simulating a heavy operation on each page
                page = reader.pages[i]
                text = page.extract_text()
                print(text)

# Example usage
vulnerable_pdf_processing("example.pdf")