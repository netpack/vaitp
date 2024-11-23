import mimetypes
from notebook.utils import is_valid_mime_type

def safe_mime_type(file_path):
    mime_type, _ = mimetypes.guess_type(file_path)
    if not is_valid_mime_type(mime_type):
        raise ValueError("Invalid MIME type detected.")
    return mime_type

def handle_uploaded_file(file):
    try:
        mime_type = safe_mime_type(file.filename)
        # Proceed with processing the file safely
    except ValueError as e:
        print(f"Error: {e}")
        # Handle the error appropriately