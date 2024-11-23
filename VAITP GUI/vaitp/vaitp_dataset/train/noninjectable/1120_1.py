import os

def upload_template(user, template_path, upload_folder):
    # No validation on the upload folder
    # Directly allows changing the download folder
    # This can lead to arbitrary file uploads
    # Proceed with the upload
    # Here you would add the logic to handle the actual file upload
    print(f"Uploading template from {template_path} to {upload_folder}")

# Example usage
upload_template('authenticated_user', 'template.py', '/some/unsafe/directory')