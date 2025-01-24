
class User:
    def __init__(self, username, role):
        self.username = username
        self.role = role
        self.session_id = None

class VirtualMachine:
    def __init__(self):
        self.allowed_roles = ['admin', 'developer']  # Define roles that can access the VM
        self.user_sessions = {}

    def login(self, user):
        if user.role in self.allowed_roles:
            # Generate and assign a unique session ID to the user
            user.session_id = self._generate_session_id()
            self.user_sessions[user.session_id] = user
            print(f"{user.username} logged in successfully.")
        else:
            print(f"Access denied for {user.username}. Insufficient privileges.")

    def execute_code(self, user, code):
        if user.session_id in self.user_sessions:
            # Verify that the session ID is valid and active
            if self._validate_session_id(user.session_id):
                # Execute code only if the user has the right role
                if user.role == 'admin':
                    exec(code)  # Dangerous operation, only for admin
                else:
                    print(f"User  {user.username} is not authorized to execute this code.")
            else:
                print(f"Invalid or expired session for {user.username}.")
        else:
            print(f"User  {user.username} is not logged in.")

    def _generate_session_id(self):
        # Implement a secure method to generate a unique and time-limited session ID
        # ...

    def _validate_session_id(self, session_id):
        # Implement a method to validate that the session ID is still active and has not expired
        # ...

# Example usage
admin_user = User("admin_user", "admin")
dev_user = User("dev_user", "developer")
guest_user = User("guest_user", "guest")

vm = VirtualMachine()
vm.login(admin_user)  # Should succeed
vm.login(dev_user)    # Should succeed
vm.login(guest_user)  # Should fail

# Only admin can execute code
vm.execute_code(admin_user, 'print("Admin executing code - Should work")')
vm.execute_code(guest_user, 'print("Guest executing code - Should fail")')