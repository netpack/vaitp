import subprocess
import shlex

def run_gcov(file_path):
    # Use shlex.quote to sanitize the input
    command = ["gcov", file_path]

    # Execute the command with subprocess.Popen, avoiding shell=True
    subprocess.Popen(command)

# Example of a malicious input
malicious_input = "file.c; cat /etc/passwd"
run_gcov(malicious_input)