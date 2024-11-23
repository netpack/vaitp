def unsafe_file_write(file_path, content):
    # Vulnerable function that allows overwriting any file
    with open(file_path, 'w') as file:
        file.write(content)

# Example usage
unsafe_file_write('/path/to/executable.py', 'print("Malicious code execution")')