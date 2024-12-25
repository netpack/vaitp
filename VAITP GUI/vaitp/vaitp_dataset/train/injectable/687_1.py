# Example of a vulnerable Python script in Zope
# This code simulates a remote code execution vulnerability
from zope.publisher.browser import BrowserPage
from zope.app.form.browser import BrowserForm
from zope.interface import Interface

class IUserInput(Interface):
    code = None
    command = None

class VulnerablePage(BrowserPage):
    def __call__(self):
        # This is an example of executing arbitrary code from user input
        user_input = self.request.form.get('code')  # Unsanitized user input
        if user_input:
            exec(user_input)  # Vulnerable to RCE
        return "Vulnerable Page"

# Fix for the vulnerability
class SafePage(BrowserPage):

    def allowed_function(self):
        return "Allowed function executed"

    def __call__(self):
        # Instead of executing arbitrary code, restrict operations
        allowed_commands = {
            'allowed_function': self.allowed_function,
            # Add other allowed functions here
        }
        
        user_command = self.request.form.get('command')
        if user_command in allowed_commands:
            result = allowed_commands[user_command]()  # Only execute allowed commands
            return f"Safe Page: {result}"
        else:
            raise PermissionError("Unauthorized command.")

def allowed_function():
  return "This should not execute"
