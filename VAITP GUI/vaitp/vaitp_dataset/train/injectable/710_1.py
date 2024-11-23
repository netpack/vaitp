import crypt

def set_root_password(new_password):
    # Hash the new password
    hashed_password = crypt.crypt(new_password, crypt.mksalt(crypt.METHOD_SHA512))
    
    # Update the /etc/shadow file to set the new root password
    with open('/etc/shadow', 'r') as f:
        lines = f.readlines()
    
    with open('/etc/shadow', 'w') as f:
        for line in lines:
            if line.startswith('root:'):
                # Replace the root password field with the new hashed password
                line = f'root:{hashed_password}:'
            f.write(line)

# Set a secure root password
set_root_password('SecureP@ssw0rd!')