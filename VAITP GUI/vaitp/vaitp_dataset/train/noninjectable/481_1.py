def insecure_include(file_path):
    # Directly include the contents of the specified file without validation
    with open(file_path, 'r') as file:
        return file.read()

# Example usage
# This allows arbitrary file inclusion, which can lead to sensitive data exposure
content = insecure_include("/etc/passwd")  # Example of including a sensitive file
print(content)