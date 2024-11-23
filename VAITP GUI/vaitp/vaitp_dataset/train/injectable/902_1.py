import os
import secrets

# Set a secure JWT_SECRET
JWT_SECRET = secrets.token_hex(32)  # Generates a random 64-character hex string

# Example function to handle file uploads
def upload_file(file):
    # Ensure the upload directory is secure and does not allow arbitrary paths
    upload_dir = '/path/to/uploads/'
    safe_filename = secure_filename(file.filename)  # Implement secure_filename to sanitize input
    file_path = os.path.join(upload_dir, safe_filename)

    # Check file type and size (additional security measures)
    if allowed_file(file.filename) and file.size < MAX_FILE_SIZE:
        file.save(file_path)
    else:
        raise ValueError("Invalid file type or size.")

# Function to sanitize filenames
def secure_filename(filename):
    return os.path.basename(filename)  # Simple sanitization to prevent directory traversal

# Function to check allowed file types
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'txt'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ensure NODE_ENV is set to production in a secure deployment
os.environ['NODE_ENV'] = 'production'