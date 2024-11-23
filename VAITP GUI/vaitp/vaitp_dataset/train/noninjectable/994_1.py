# Example of a vulnerable PythonScript execution

def execute_user_script(script):
    # Directly execute user-provided script without restrictions
    exec(script)

# Example usage
user_script = """
# This script can cause a denial of service
import time

# Infinite loop to consume resources
while True:
    time.sleep(1)
"""

execute_user_script(user_script)