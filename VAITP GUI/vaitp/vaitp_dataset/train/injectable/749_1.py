import os
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.files.storage import FileSystemStorage
from django.conf import settings
from io import BytesIO

class SecureFileSystemStorage(FileSystemStorage):
    def get_available_name(self, name, max_length=None):
        # Ensure the directory exists with the correct permissions
        directory = os.path.dirname(name)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, mode=settings.FILE_UPLOAD_DIRECTORY_PERMISSIONS, exist_ok=True)
        return super().get_available_name(name, max_length)

# Usage example
file_storage = SecureFileSystemStorage()
# Assume this is your uploaded file
content = b"This is the content of the file."
uploaded_file = InMemoryUploadedFile(
    file=BytesIO(content),
    field_name='myfile',
    name='test.txt',
    content_type='text/plain',
    size=len(content),
    charset=None
)
file_storage.save(uploaded_file.name, uploaded_file)