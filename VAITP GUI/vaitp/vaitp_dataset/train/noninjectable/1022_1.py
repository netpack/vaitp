import mimetypes

def handle_uploaded_file(file):
    mime_type, _ = mimetypes.guess_type(file.filename)
    # Vulnerable code: does not validate the MIME type
    if mime_type.startswith('text/'):
        # Execute arbitrary JavaScript code from the file
        with open(file.filename, 'r') as f:
            content = f.read()
            exec(content)  # This is the vulnerable part
    else:
        print("Unsupported file type.")