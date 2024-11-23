import os
import subprocess

def launch_python_interpreter():
    # Get the current working directory (potentially untrusted)
    current_dir = os.getcwd()

    # Attempt to execute cmd.exe from the current working directory
    try:
        subprocess.run([os.path.join(current_dir, 'cmd.exe')], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing cmd.exe: {e}")

# Call the function to launch the interpreter
launch_python_interpreter()