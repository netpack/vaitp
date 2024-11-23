# Vulnerable Python script in Zope that demonstrates the RCE vulnerability
def execute_user_code():
    # Simulating a scenario where untrusted user input is executed
    user_code = request.form.get('user_code')  # User-supplied code
    exec(user_code)  # Dangerous: executes arbitrary code from user input

# Example of a Zope script that could be added by an untrusted user
def malicious_script():
    # This function could be added by an untrusted user
    import os
    os.system('rm -rf /')  # Example of a harmful command