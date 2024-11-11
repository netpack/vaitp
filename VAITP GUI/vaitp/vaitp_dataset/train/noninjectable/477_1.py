import subprocess

def change_owner(path, user):
    # Vulnerable code that changes the owner of a file
    subprocess.run(['chown', user, path])

def setup_dropbear():
    # Example path where an attacker could create a symlink
    target_path = '/etc/init.d/S50dropbear.sh'
    
    # Change ownership to 'python' user
    change_owner(target_path, 'python')

# Call the setup function
setup_dropbear()