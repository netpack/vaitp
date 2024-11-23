import PyPDF2

def safe_read_pdf(file_path):
    with open(file_path, "rb") as file:
        reader = PyPDF2.PdfReader(file)
        for page in reader.pages:
            try:
                content = page.extract_text()
                print(content)
            except Exception as e:
                print(f"Error reading page: {e}")

# Example usage
safe_read_pdf("example.pdf")