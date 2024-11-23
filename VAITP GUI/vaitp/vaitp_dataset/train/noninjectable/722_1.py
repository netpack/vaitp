import maya.cmds as cmds

def load_file(file_path):
    # Load the file directly, potentially executing arbitrary MEL commands
    cmds.file(file_path, i=True, ignoreVersion=True)

# Example usage
# load_file('path/to/vulnerable_file.ma')