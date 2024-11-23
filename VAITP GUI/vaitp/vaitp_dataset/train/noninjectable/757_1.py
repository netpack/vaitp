def vulnerable_open(file_path, mode):
    # This function does not validate the mode or directory
    return open(file_path, mode)

# Example usage
with vulnerable_open('/some_arbitrary_path/my_file.txt', 'w') as f:
    f.write('This could be any file!')