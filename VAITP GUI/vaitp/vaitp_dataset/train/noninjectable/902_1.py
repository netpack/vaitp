import os

# Example of vulnerable configuration
JWT_SECRET = 'dev'  # Easily guessable string
NODE_ENV = 'development'  # Non-production environment

# Function to handle file uploads
def upload_file(file):
    upload_dir = '/uploads/'  # Arbitrary upload directory
    file_path = os.path.join(upload_dir, file.filename)

    # Directly saving the file without validation
    # Assuming 'file' object has a save method like a Flask FileStorage object
    try:
        file.save(file_path)  # Vulnerable to arbitrary file uploads
    except AttributeError:
        print("Error: 'file' object does not have a 'save' method. Please provide a proper file-like object.")
        return

# Function to register a new account
def register_account(username, password):
    # Simplified registration logic
    print(f"Account registered for {username}")

# Example usage
# Assume 'file' is an object with a 'filename' attribute and a 'save' method
# Create a dummy file object for testing
class MockFile:
    def __init__(self, filename, content):
        self.filename = filename
        self.content = content

    def save(self, filepath):
        with open(filepath, 'wb') as f:
            f.write(self.content)


file = MockFile('test.txt', b'This is a test file.')
upload_file(file)
register_account('attacker', 'password123')