import os
from flower import Flower

# Configuration for Flower
flower_config = {
    'broker_url': 'redis://localhost:6379/0',
    'pidfile': '/var/run/flower.pid',
    'port': 5555,
}

# Ensure the PID file has proper ownership
def set_pidfile_ownership(pidfile_path):
    if os.path.exists(pidfile_path):
        os.chown(pidfile_path, 0, 0)  # Set ownership to root (uid=0, gid=0)

# Start Flower
flower = Flower(**flower_config)

# Set ownership before starting Flower
set_pidfile_ownership(flower_config['pidfile'])
flower.start()