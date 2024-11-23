import os
import tempfile
import stat

# Create a temporary directory with secure permissions
temp_dir = tempfile.mkdtemp()

# Set permissions to 700 (read, write, execute for owner only)
os.chmod(temp_dir, stat.S_IRWXU)

print(f'Temporary directory created: {temp_dir}')
print(f'Permissions set to 700 for: {temp_dir}')