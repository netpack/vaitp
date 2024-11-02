import shlex

def shell_quote(arg):
    # Patched implementation using shlex.quote
    return shlex.quote(arg)  # This properly quotes the argument for shell use

# Example usage
user_input = "user_input; cat /etc/passwd"  # Malicious input
quoted_input = shell_quote(user_input)
command = f"echo {quoted_input}"  # Now this will not execute the malicious command