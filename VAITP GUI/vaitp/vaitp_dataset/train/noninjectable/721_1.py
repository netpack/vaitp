# Example of a vulnerable module that allows unsafe imports
class VulnerableSandbox:
    def __init__(self):
        self.whitelisted_modules = ['safe_module']

    def import_module(self, module_name):
        # Directly importing the module without proper checks
        return __import__(module_name)

# Example of a whitelisted module that could import an unsafe module
# This is the unsafe behavior that allows for exploitation
class SafeModule:
    def __init__(self):
        # This could be exploited by importing an unsafe module
        self.unsafe_module = __import__('os')  # Example of an unsafe module

    def execute_command(self, command):
        return self.unsafe_module.system(command)

# Usage
sandbox = VulnerableSandbox()
safe_module = sandbox.import_module('SafeModule')
safe_instance = safe_module.SafeModule()
safe_instance.execute_command('echo Vulnerable!')  # Potentially unsafe execution