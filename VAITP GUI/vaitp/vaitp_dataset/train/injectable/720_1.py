import subprocess

def secure_chpasswd(username, password):
    # Ensure the password is not set to a cleartext value that allows bypassing restrictions
    if password == "!":
        raise ValueError("Setting the password to '!' is not allowed for security reasons.")

    # Use the -e option to ensure the password is encrypted
    command = ["chpasswd", "-e"]
    input_str = f"{username}:{password}".encode()
    subprocess.run(command, input=input_str, check=True)

# Example usage
try:
    secure_chpasswd('root', 'test_password')
except ValueError as e:
    print(e)