import os
import subprocess

def secure_sudo_configuration():
    # Ensure that the sudoers file is properly configured
    sudoers_file = '/etc/sudoers'
    
    # Backup the original sudoers file
    backup_file = '/etc/sudoers.bak'
    subprocess.run(['cp', sudoers_file, backup_file])

    # Properly set permissions for the sudoers file
    os.chmod(sudoers_file, 0o440)

    # Add a secure sudo configuration
    with open(sudoers_file, 'a') as f:
        f.write('\n# Secure sudoers configuration\n')
        f.write('Defaults    env_reset\n')
        f.write('Defaults    mail_badge\n')
        f.write('Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n')
        f.write('Defaults    visiblepw\n')

secure_sudo_configuration()