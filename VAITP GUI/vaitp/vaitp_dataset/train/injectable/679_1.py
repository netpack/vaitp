import threading

# Thread-safe wrapper for password checking
class PasswordChecker:
    def __init__(self):
        self.lock = threading.Lock()

    def check_password(self, password):
        with self.lock:
            # Simulate password checking logic
            return self._password_checker_logic(password)

    def _password_checker_logic(self, password):
        # Replace this with the actual password checking logic
        # For demonstration, let's assume it returns True if the password is strong
        return len(password) >= 8  # Example condition for a strong password

# Usage
password_checker = PasswordChecker()

def check_user_password(password):
    if password_checker.check_password(password):
        print("Password is strong.")
    else:
        print("Password is weak.")

# Example usage
check_user_password("example_password")