import os

class VulnerableClass:
    def execute_command(self, command):
        # Vulnerable to command injection
        os.system(command)

# Example of how the vulnerability could be exploited
vulnerable_instance = VulnerableClass()
vulnerable_instance.execute_command("rm -rf /")  # An example of an arbitrary command