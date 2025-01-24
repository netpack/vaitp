import os
import stat
from flower.command import Flower
import getpass

# Configuration for Flower
flower_config = {
    'broker_url': 'redis://localhost:6379/0',
    'pidfile': '/var/run/flower.pid',
    'port': 5555,
}

# Ensure the PID file has proper ownership
def set_pidfile_ownership(pidfile_path):
    if os.path.exists(pidfile_path):
        try:
            uid = os.getuid()
            gid = os.getgid()
            if uid == 0: #Only try to chown if we are root, otherwise just skip
                os.chown(pidfile_path, uid, gid)
            os.chmod(pidfile_path, stat.S_IRUSR | stat.S_IWUSR)  # Set read/write permissions for the user
        except PermissionError:
             print(f"Permission denied to change ownership of {pidfile_path}. Ensure the script has sufficient privileges.")
        except OSError as e:
            print(f"Error changing permissions of {pidfile_path}: {e}")


# Start Flower
flower = Flower(**flower_config)

# Set ownership before starting Flower
set_pidfile_ownership(flower_config['pidfile'])
flower.start()