# Example of a fix for CVE-2023-32682 in a hypothetical Synapse configuration

class User:
    def __init__(self, username, password, is_active):
        self.username = username
        self.password = password
        self.is_active = is_active

    def deactivate(self):
        self.is_active = False
        self.password = None  # Clear password on deactivation

class AuthService:
    def __init__(self):
        self.users = {}

    def add_user(self, username, password):
        self.users[username] = User(username, password, True)

    def deactivate_user(self, username):
        user = self.users.get(username)
        if user:
            user.deactivate()

    def update_password(self, username, new_password):
        user = self.users.get(username)
        if user and user.is_active:
            user.password = new_password

    def login(self, username, password):
        user = self.users.get(username)
        # Prevent deactivated users from logging in
        if user and user.is_active and user.password == password:
            return True
        return False

# Example usage
auth_service = AuthService()
auth_service.add_user("john_doe", "secure_password")
auth_service.deactivate_user("john_doe")

# Attempting to login with a deactivated user
assert not auth_service.login("john_doe", "secure_password")  # Should return False