import os

def handle_download(file_name, mime_type):
    if mime_type == 'text/plain':
        if not isinstance(file_name, str):
            print("Invalid file name.")
            return

        if '..' in file_name or file_name.startswith('/'):
             print("Invalid file name.")
             return
        
        if file_name.endswith('.py'):
            print("File is a Python script. Please open it with a text editor.")
        else:
            try:
                with open(file_name, 'r') as f:
                    content = f.read()
                    print(content)
            except FileNotFoundError:
                print("File not found.")
            except IOError:
                print("Error reading file.")
    else:
        pass