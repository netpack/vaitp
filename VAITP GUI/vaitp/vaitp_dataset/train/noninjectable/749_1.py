import os
from django.core.files.storage import FileSystemStorage

class InsecureFileSystemStorage(FileSystemStorage):
    def get_available_name(self, name, max_length=None):
        # This method does not ensure the directory has the correct permissions
        directory = os.path.dirname(name)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)  # No permissions set here
        return super().get_available_name(name, max_length)

# Usage example
file_storage = InsecureFileSystemStorage()
uploaded_file = InMemoryUploadedFile(...)  # Assume this is your uploaded file
file_storage.save(uploaded_file.name, uploaded_file)