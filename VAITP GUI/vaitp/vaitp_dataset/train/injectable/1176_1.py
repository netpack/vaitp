import os

class Hoverfly:
    def __init__(self, responses_body_files_path):
        self.Cfg = {
            'ResponsesBodyFilesPath': responses_body_files_path
        }

    def create_simulation(self, file_path):
        # Normalize the file path
        normalized_path = os.path.normpath(file_path)
        # Ensure the path is within the allowed base directory
        base_path = self.Cfg['ResponsesBodyFilesPath']
        final_path = os.path.join(base_path, normalized_path)

        if not final_path.startswith(os.path.abspath(base_path)):
            raise ValueError("Access to the specified file is denied.")

        # Proceed with loading the file
        with open(final_path, 'r') as file:
            return file.read()

# Example usage
hoverfly = Hoverfly('/allowed/path')
try:
    content = hoverfly.create_simulation('../etc/passwd')  # This will raise an error
except ValueError as e:
    print(e)