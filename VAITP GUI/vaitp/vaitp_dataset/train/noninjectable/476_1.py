# Vulnerable code allowing untrusted execution
from AccessControl import getSecurityManager

def execute_user_code(user_code):
    # Assuming the security manager is set up to check permissions
    if getSecurityManager().checkPermission('Access contents information', None):
        exec(user_code)  # Dangerous: allows execution of arbitrary code
    else:
        raise Exception("Unauthorized access")

# User input (untrusted)
user_input = "cat /etc/passwd"
execute_user_code(user_input)