class ActiveXControl:
    def read_file(self, file_path):
        with open(file_path, 'r') as file:
            return file.read()

# Example usage
activex_control = ActiveXControl()
content = activex_control.read_file("C:/path/to/arbitrary/file.txt")  # Vulnerable to reading any file
print(content)