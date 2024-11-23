class User:
    def __init__(self, username, role):
        self.username = username
        self.role = role

class VirtualMachine:
    def __init__(self):
        self.allowed_roles = ['admin', 'developer']  # Define roles that can access the VM
        self.user_sessions = {}

    def login(self, user):
        if user.role in self.allowed_roles:
            self.user_sessions[user.username] = user
            print(f"{user.username} logged in successfully.")
        else:
            print(f"Access denied for {user.username}. Insufficient privileges.")

    def execute_code(self, user, code):
        if user.username in self.user_sessions:
            # Execute code only if the user has the right role
            if user.role == 'admin':
                exec(code)  # Dangerous operation, only for admin
            else:
                print(f"User  {user.username} is not authorized to execute this code.")
        else:
            print(f"User  {user.username} is not logged in.")

# Example usage
admin_user = User("admin_user", "admin")
dev_user = User("dev_user", "developer")
guest_user = User("guest_user", "guest")

vm = VirtualMachine()
vm.login(admin_user)  # Should succeed
vm.login(dev_user)    # Should succeed
vm.login(guest_user)  # Should fail

# Only admin can execute code
vm.execute_code(admin_user, 'print