import os
import subprocess

def secure_sudo_configuration():
    # Ensure that the sudoers file is properly configured
    sudoers_file = '/etc/sudoers'
    
    # Backup the original sudoers file
    backup_file = '/etc/sudoers.bak'
    try:
        subprocess.run(['cp', sudoers_file, backup_file], check=True)
    except subprocess.CalledProcessError as e:
         print(f"Error backing up sudoers file: {e}")
         return
    
    # Properly set permissions for the sudoers file
    try:
        os.chmod(sudoers_file, 0o440)
    except OSError as e:
        print(f"Error changing permissions of sudoers file: {e}")
        return

    # Add a secure sudo configuration
    try:
        with open(sudoers_file, 'a') as f:
            f.write('\n# Secure sudoers configuration\n')
            f.write('Defaults    env_reset\n')
            f.write('Defaults    mail_badpass\n')
            f.write('Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n')
            f.write('Defaults    visiblepw\n')
    except OSError as e:
        print(f"Error writing to sudoers file: {e}")
        return

secure_sudo_configuration()