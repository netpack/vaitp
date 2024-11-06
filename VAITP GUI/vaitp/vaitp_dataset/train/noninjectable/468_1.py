import os

def create_temp_file():
    # Insecurely creating a temporary file in /tmp
    temp_file_path = '/tmp/tempfile.txt'
    with open(temp_file_path, 'w') as temp_file:
        temp_file.write('This is a temporary file.')
    return temp_file_path

# Usage
temp_file = create_temp_file()
print(f'Temporary file created at: {temp_file}')