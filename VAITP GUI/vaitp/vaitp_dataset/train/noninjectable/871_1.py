import PyPDF2

def read_pdf_with_vulnerability(file_path):
    with open(file_path, "rb") as file:
        reader = PyPDF2.PdfReader(file)
        for page in reader.pages:
            # This code may lead to an infinite loop if the PDF is crafted maliciously
            content_stream = page.get_contents()
            for obj in content_stream:
                if obj == b'EI':
                    break
                # Process the content stream
                print(obj)

# Example usage
read_pdf_with_vulnerability("vulnerable_example.pdf")