import os

class Hoverfly:
    def __init__(self, responses_body_files_path):
        self.Cfg = {
            'ResponsesBodyFilesPath': responses_body_files_path
        }

    def create_simulation(self, file_path):
        # Directly join the user-specified file path with the base path
        final_path = os.path.join(self.Cfg['ResponsesBodyFilesPath'], file_path)

        # Attempt to read the file without validation
        with open(final_path, 'r') as file:
            return file.read()

# Example usage
hoverfly = Hoverfly('/allowed/path')
# An attacker could exploit this by using ../ to access restricted files
content = hoverfly.create_simulation('../etc/passwd')  # This could potentially read sensitive files
print(content)