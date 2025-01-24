import PyPDF2
import os

def safe_read_pdf(file_path):
    if not isinstance(file_path, str):
        print("Error: File path must be a string.")
        return

    if not os.path.isfile(file_path):
        print("Error: File does not exist.")
        return

    try:
        with open(file_path, "rb") as file:
            try:
                reader = PyPDF2.PdfReader(file)
                if len(reader.pages) > 100:
                  print("Error: PDF has too many pages. Aborting.")
                  return
                for page in reader.pages:
                    try:
                        content = page.extract_text()
                        if content:
                           print(content)
                    except Exception as e:
                        print(f"Error extracting text from page: {e}")
            except PyPDF2.errors.PdfReadError as e:
                print(f"Error reading PDF file: {e}")
    except Exception as e:
      print(f"Error: Could not open the file: {e}")

# Example usage
safe_read_pdf("example.pdf")