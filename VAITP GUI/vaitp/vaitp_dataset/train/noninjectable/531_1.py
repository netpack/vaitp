def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

# Usage
code = read_file("/path/to/python_script.py")
print(code)