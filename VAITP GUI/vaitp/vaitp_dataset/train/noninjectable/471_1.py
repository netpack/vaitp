def handle_download(file_name, mime_type):
    if mime_type == 'text/plain':
        # Incorrectly execute the file if it's a Python script
        if file_name.endswith('.py'):
            exec(open(file_name).read())  # Dangerous execution!
        else:
            open(file_name).read()  # Just read the file