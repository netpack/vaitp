def open_project_file(file_name):
    # Vulnerable approach: directly using the user input to open a file
    with open(file_name, 'r') as file:
        data = file.read()
    return data