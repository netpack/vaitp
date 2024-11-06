import tempfile

def create_temp_file():
    # Securely creating a temporary file using tempfile
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b'This is a temporary file.')
        temp_file_path = temp_file.name
    return temp_file_path

# Usage
temp_file = create_temp_file()
print(f'Temporary file created at: {temp_file}')