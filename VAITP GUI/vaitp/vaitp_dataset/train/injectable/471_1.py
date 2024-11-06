def handle_download(file_name, mime_type):
    if mime_type == 'text/plain':
        # Do not execute Python files; treat them as plain text
        if file_name.endswith('.py'):
            print("File is a Python script. Please open it with a text editor.")
        else:
            content = open(file_name).read()  # Read the file safely
            print(content)
    else:
        # Handle other MIME types appropriately
        pass