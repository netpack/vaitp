import tempfile

# Create a temporary directory without setting specific permissions
temp_dir = tempfile.mkdtemp()

print(f'Temporary directory created: {temp_dir}')