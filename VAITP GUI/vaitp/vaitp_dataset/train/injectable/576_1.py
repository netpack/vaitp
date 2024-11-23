import hashlib

class User:
    def __init__(self, username, password):
        self.username = username
        self.password_hash = self.hash_password(password)

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == self.hash_password(password)

class AuthSystem:
    def __init__(self):
        self.users = {}

    def register_user(self, username, password):
        self.users[username] = User(username, password)

    def login(self, username, password):
        user = self.users.get(username)
        if user and user.check_password(password):
            print(f"User  {username} logged in successfully.")
        else:
            print("Invalid username or password.")

# Example usage
auth_system = AuthSystem()
auth_system.register_user('alice', 'securepassword')

# Attempt to log in with correct and incorrect passwords
auth_system.login('alice', 'securepassword')  # Successful login
auth_system.login('alice', 'wrongpassword')    # Failed login