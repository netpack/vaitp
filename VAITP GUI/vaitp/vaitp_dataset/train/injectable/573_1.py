import os
import subprocess
import tempfile

def secure_sudo_configuration():
    sudoers_file = '/etc/sudoers'
    backup_file = '/etc/sudoers.bak'
    
    try:
        subprocess.run(['cp', sudoers_file, backup_file], check=True)
    except subprocess.CalledProcessError as e:
         print(f"Error backing up sudoers file: {e}")
         return
    
    try:
        os.chmod(sudoers_file, 0o440)
    except OSError as e:
        print(f"Error changing permissions of sudoers file: {e}")
        return

    try:
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
            tmp_file.write('# Secure sudoers configuration\n')
            tmp_file.write('Defaults    env_reset\n')
            tmp_file.write('Defaults    mail_badpass\n')
            tmp_file.write('Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n')
            tmp_file.write('Defaults    visiblepw\n')
            tmp_file_name = tmp_file.name

        subprocess.run(['visudo', '-c', '-f', tmp_file_name], check=True)
        subprocess.run(['cp', tmp_file_name, sudoers_file], check=True)
        os.unlink(tmp_file_name)

    except subprocess.CalledProcessError as e:
        print(f"Error writing to sudoers file: {e}")
        if os.path.exists(tmp_file_name):
           os.unlink(tmp_file_name)
        return
    except OSError as e:
        print(f"Error writing to sudoers file: {e}")
        return

secure_sudo_configuration()