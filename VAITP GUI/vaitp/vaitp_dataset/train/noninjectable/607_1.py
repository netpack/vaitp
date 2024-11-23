class UserSettings:
    def __init__(self):
        self.admins = set()

    def add_admin(self, username, pin):
        # Vulnerable code: directly executing the pin as code
        exec(f"self.admins.add('{username}') if '{pin}' == '1234' else None")

# Example usage
settings = UserSettings()
settings.add_admin("new_admin", "1234")  # Valid pin, adds admin
settings.add_admin("malicious_user", "__import__('os').system('rm -rf /')")  # Arbitrary code execution