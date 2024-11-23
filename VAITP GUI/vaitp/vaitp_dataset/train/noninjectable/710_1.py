def set_default_root_password():
    # Set the default root password to an insecure value
    root_password = '!'  # Vulnerable default password

    # Simulate storing the password in a configuration file
    with open('/etc/shadow', 'a') as f:
        f.write(f'root:{root_password}:\n')

# Set the default root password to the insecure value
set_default_root_password()