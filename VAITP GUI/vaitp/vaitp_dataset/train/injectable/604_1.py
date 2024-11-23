import os
import stat

# Path to the local_settings file
file_path = '/etc/openstack-dashboard/local_settings'

# Change the file permissions to restrict access
os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # Only owner can read and write