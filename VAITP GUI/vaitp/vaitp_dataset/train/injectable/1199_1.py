import os
import sys
import subprocess

# Safe execution of a Python script without allowing arbitrary PYTHONPATH
def safe_execute(script_path):
    # Ensure PYTHONPATH is not modified
    env = os.environ.copy()
    env['PYTHONPATH'] = ''
    try:
      subprocess.run([sys.executable, script_path], env=env, check=True)
    except subprocess.CalledProcessError as e:
      print(f"Error executing script: {e}")


# Example usage
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python safe_execute.py <script_path>")
        sys.exit(1)
    safe_execute(sys.argv[1])
