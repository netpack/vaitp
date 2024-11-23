def create_folder(folder_name):
    # Vulnerable code: directly using folder_name without sanitization
    folder_path = '/path/to/folders/' + folder_name
    # Logic to create the folder using folder_path
    # ...

# Example usage
create_folder("<script>alert('XSS');</script>")