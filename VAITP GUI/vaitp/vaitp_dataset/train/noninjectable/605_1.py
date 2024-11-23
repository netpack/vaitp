class User:
    def __init__(self, username, has_scripting_permissions):
        self.username = username
        self.has_scripting_permissions = has_scripting_permissions

class DashboardEditor:
    def __init__(self, user):
        self.user = user

    def edit_dashboard(self, script):
        # Vulnerability: No permission check before executing the script
        self.execute_script(script)

    def execute_script(self, script):
        # Implementation of script execution
        print(f"Executing script: {script}")

# Example usage
user_without_permission = User("guest", False)
editor = DashboardEditor(user_without_permission)

# This will execute the script despite the user not having permissions
editor.edit_dashboard("print('Hello, Guest! This should not be allowed.')")