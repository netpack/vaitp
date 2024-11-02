# Before the patch: Vulnerable code snippet
def read_file(file_name):
    with open(file_name, 'r') as file:
        return file.read()