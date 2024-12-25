import subprocess

def unsafe_script_invoke(script):
    # Directly executing user-supplied script
    try:
        subprocess.run(script, shell=True, check=True, executable='/bin/bash')
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
    except Exception as e:
         print(f"An unexpected error occurred: {e}")



# Example usage
user_input_script = "ls"  # Arbitrary code execution
unsafe_script_invoke(user_input_script)