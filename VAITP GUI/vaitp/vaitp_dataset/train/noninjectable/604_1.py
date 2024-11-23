import os

# Path to the local_settings file
file_path = '/etc/openstack-dashboard/local_settings'

# Simulating the vulnerability by setting world-readable permissions
os.chmod(file_path, 0o644)  # Owner can read and write, group and others can read