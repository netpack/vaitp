import os

# Example of vulnerable configuration
JWT_SECRET = 'dev'  # Easily guessable string
NODE_ENV = 'development'  # Non-production environment

# Function to handle file uploads
def upload_file(file):
    upload_dir = '/uploads/'  # Arbitrary upload directory
    file_path = os.path.join(upload_dir, file.filename)

    # Directly saving the file without validation
    file.save(file_path)  # Vulnerable to arbitrary file uploads

# Function to register a new account
def register_account(username, password):
    # Simplified registration logic
    print(f"Account registered for {username}")

# Example usage
# Assume 'file' is an object with a 'filename' attribute and a 'save' method
upload_file(file)
register_account('attacker', 'password123')