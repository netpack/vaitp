class ScriptFuServer:
    def __init__(self):
        self.commands = {
            "run_script": self.run_script,
            # Other commands...
        }
        self.authenticated_users = set()  # Store authenticated users

    def authenticate(self, user_token):
        # Simple token-based authentication
        if user_token == "valid_token":  # Replace with a more secure check
            self.authenticated_users.add(user_token)
            return True
        return False

    def handle_request(self, request):
        user_token = request.get("user_token")
        if user_token not in self.authenticated_users:
            print("Unauthorized access")
            return
        
        command = request.get("command")
        if command in self.commands:
            self.commands[command](request)
        else:
            print("Unknown command")

    def run_script(self, request):
        script_name = request.get("script_name")
        print(f"Running script: {script_name}")
        # Execute the script only if the user is authenticated