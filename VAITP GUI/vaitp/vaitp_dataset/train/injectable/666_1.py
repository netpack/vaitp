class VDC:
    def __init__(self, name):
        self.name = name
        self.files = {}

    def create_file(self, filename, content):
        self.files[filename] = content

    def delete_file(self, filename, user_role):
        if user_role != 'admin':
            raise PermissionError("Access denied: You do not have permission to delete files in this VDC.")
        if filename in self.files:
            del self.files[filename]
        else:
            raise FileNotFoundError("File not found.")

# Example of usage
vdc1 = VDC("VDC1")
vdc1.create_file("important_file.txt", "This is important content.")

# Attempting to delete a file with non-admin role
try:
    vdc1.delete_file("important_file.txt", user_role='user')  # Should raise PermissionError
except PermissionError as e:
    print(e)

# Admin user deleting the file
try:
    vdc1.delete_file("important_file.txt", user_role='admin')  # Should succeed
    print("File deleted successfully.")
except Exception as e:
    print(e)