# Vulnerable version of the Togglee package with a code execution backdoor

class Togglee:
    def __init__(self):
        self.settings = {}

    def set_setting(self, key, value):
        # Vulnerable to arbitrary code execution
        self.settings[key] = value

    def execute_code(self, code):
        # Dangerous method that executes arbitrary code
        exec(code)

# Example usage
togglee = Togglee()
togglee.set_setting('setting1', 'value1')
# An attacker could exploit this to execute arbitrary code
togglee.execute_code('import os; os.system("echo Vulnerable!")')