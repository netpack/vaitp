import maya.cmds as cmds

def safe_load_file(file_path):
    # Check the file extension to ensure it's a trusted format
    if not (file_path.endswith('.ma') or file_path.endswith('.mb')):
        raise ValueError("Invalid file type. Only .ma and .mb files are allowed.")

    # Implement a safe loading mechanism
    try:
        # Load the file without executing any MEL commands
        cmds.file(file_path, i=True, ignoreVersion=True, options="v=0;")
    except Exception as e:
        print(f"Error loading file: {e}")

# Example usage
# safe_load_file('path/to/safe_file.ma')