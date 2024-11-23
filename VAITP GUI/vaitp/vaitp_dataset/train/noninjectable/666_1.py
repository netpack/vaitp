class VDC:
    def __init__(self, name):
        self.name = name
        self.files = {}

    def create_file(self, filename, content):
        self.files[filename] = content

    def delete_file(self, filename, user_role):
        # Vulnerability: No proper access control checks
        if filename in self.files:
            del self.files[filename]  # Allows any user to delete files regardless of role
        else:
            raise FileNotFoundError("File not found.")

# Example of usage
vdc1 = VDC("VDC1")
vdc1.create_file("important_file.txt", "This is important content.")

# Non-admin user deleting the file
try:
    vdc1.delete_file("important_file.txt", user_role='user')  # Should succeed due to lack of checks
    print("File deleted successfully.")
except Exception as e:
    print(e)