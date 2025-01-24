import os
import subprocess

def execute_command_and_log(command):
    """Executes a command and logs the output to a temporary file."""
    try:
      
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        log_file = "/tmp/framer.txt"
        with open(log_file, "a") as f:
            f.write(f"Command: {command}\n")
            f.write(f"Stdout:\n{stdout.decode()}\n")
            f.write(f"Stderr:\n{stderr.decode()}\n")
            f.write("-" * 20 + "\n")
    except Exception as e:
        print(f"Error executing command: {e}")
        
def main():
    
    # Example Usage for an SSH-like interaction that would use this
    #
    # This code represents a scenario where iTerm2 might execute commands
    # during a remote SSH session, including sensitive commands that may
    # contain secrets or personal information. This logs the outputs to the
    # vulnerable file.
    
    commands_to_run = [
        "echo 'This is a test command'",
        "ls -la /home/user/", # An example that could expose the home path
        "cat /etc/passwd", # An example that could expose password information
        "printenv", # Might reveal environment variables that hold sensetive data
        "ssh -v user@remote.server cat secret_file", # An example of a potentially sensitive command
        "git config --global --list"
    ]

    for command in commands_to_run:
      execute_command_and_log(command)


if __name__ == "__main__":
    main()