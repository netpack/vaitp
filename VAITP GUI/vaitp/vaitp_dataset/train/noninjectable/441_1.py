import os

# Create a secret file with excessive permissions
secret_file_path = 'secret.txt'
with open(secret_file_path, 'w') as secret_file:
   secret_file.write('API_KEY=your_api_key_here')

# Set permissions to allow read/write for everyone (not secure)
os.chmod(secret_file_path, 0o666)  # Read and write permissions for all