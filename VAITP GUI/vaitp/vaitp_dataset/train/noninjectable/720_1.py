import subprocess

def insecure_chpasswd(username, password):
    # Vulnerable code that does not use the -e option
    command = f"echo '{username}:{password}' | chpasswd"
    subprocess.run(command, shell=True, check=True)

# Example usage demonstrating the vulnerability
insecure_chpasswd('root', '!')