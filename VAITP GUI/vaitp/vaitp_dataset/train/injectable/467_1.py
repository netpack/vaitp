import tempfile

def create_temp_file(data):
    # Create a temporary file securely
    with tempfile.NamedTemporaryFile(delete=True) as temp_file:
        try:
            temp_file.write(data.encode())
            temp_file.flush()  # Ensure data is written to disk
            # Do something with the temp file
            # The file will be deleted automatically when closed
        except Exception as e:
            print(f"Error: {e}")