import os
import shutil
import tempfile

def vulnerable_rmtree(path):
    # This function does not check for symlinks or junctions, allowing for potential exploitation
    shutil.rmtree(path)

# Example usage
try:
    temp_dir = tempfile.gettempdir()
    # Create a directory to delete in the temporary directory
    os.mkdir(os.path.join(temp_dir, 'to_delete'))
    
    # Call the vulnerable removal function
    vulnerable_rmtree(os.path.join(temp_dir, 'to_delete'))
except Exception as e:
    print(f"Error: {e}")