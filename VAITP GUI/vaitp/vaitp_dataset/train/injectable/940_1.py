import os
import shutil
import tempfile

def safe_rmtree(path):
    # Ensure the path is owned by the current user
    if os.path.commonpath([path, tempfile.gettempdir()]) == tempfile.gettempdir():
        raise PermissionError("Attempting to delete files outside of the user's temporary directory is not allowed.")
    
    # Proceed with the deletion
    shutil.rmtree(path)

# Example usage
try:
    temp_dir = tempfile.mkdtemp()
    # Create a directory to delete
    os.mkdir(os.path.join(temp_dir, 'to_delete'))
    
    # Call the safe removal function
    safe_rmtree(os.path.join(temp_dir, 'to_delete'))
except Exception as e:
    print(f"Error: {e}")