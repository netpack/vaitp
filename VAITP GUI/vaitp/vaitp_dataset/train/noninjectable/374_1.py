def shell_quote(arg):
    # Vulnerable implementation
    return arg.replace("'", "'\\''")  # This does not handle all cases correctly

# Example usage
user_input = "user_input; cat /etc/passwd"  # Malicious input
quoted_input = shell_quote(user_input)
command = f"echo {quoted_input}"  # This could execute the malicious command