import os
import subprocess

# Function that demonstrates the vulnerability by loading scripts from the current directory
def load_gdb_script(script_name):
    # Directly load the script without any checks
    subprocess.run(["gdb", "-x", script_name])

# Example usage
load_gdb_script(".debug_gdb_scripts")