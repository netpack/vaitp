import subprocess

def secure_chpasswd(username, password):
    # Ensure the password is not set to a cleartext value that allows bypassing restrictions
    if password == "!":
        raise ValueError("Setting the password to '!' is not allowed for security reasons.")

    # Use the -e option to ensure the password is encrypted
    command = f"echo '{username}:{password}' | chpasswd -e"
    subprocess.run(command, shell=True, check=True)

# Example usage
try:
    secure_chpasswd('root', '!')
except ValueError as e:
    print(e)