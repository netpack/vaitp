import os
import subprocess

def insecure_sudo_configuration():
    # This function demonstrates an insecure sudo configuration
    sudoers_file = '/etc/sudoers'
    
    # Backup the original sudoers file
    backup_file = '/etc/sudoers.bak'
    subprocess.run(['cp', sudoers_file, backup_file])

    # Improperly set permissions for the sudoers file
    os.chmod(sudoers_file, 0o644)  # Insecure permission

    # Add insecure sudo configuration
    with open(sudoers_file, 'a') as f:
        f.write('\n# Insecure sudoers configuration\n')
        f.write('Defaults    !secure_path\n')  # Disable secure_path
        f.write('Defaults    env_reset\n')
        f.write('Defaults    visiblepw\n')

insecure_sudo_configuration()