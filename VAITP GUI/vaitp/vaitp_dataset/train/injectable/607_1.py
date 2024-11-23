# Example fix for CVE-2008-6539: Preventing static code injection in the settings

class UserSettings:
    def __init__(self):
        self.admins = set()

    def add_admin(self, username, pin):
        # Validate the pin before processing
        if self.validate_pin(pin):
            self.admins.add(username)
            print(f"User  {username} added as admin.")
        else:
            print("Invalid pin. Admin not added.")

    def validate_pin(self, pin):
        # Ensure the pin is a numeric string of a specific length
        return isinstance(pin, str) and pin.isdigit() and len(pin) == 4

# Example usage
settings = UserSettings()
settings.add_admin("new_admin", "1234")  # Valid pin
settings.add_admin("malicious_user", "abcd")  # Invalid pin, won't add