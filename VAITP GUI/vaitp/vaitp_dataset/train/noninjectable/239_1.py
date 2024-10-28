import subprocess

def run_gcov(file_path):
    # User input is taken directly without validation
    command = f"gcov {file_path}"
    
    # This will execute the command, but if file_path contains malicious input,
    # it can lead to command injection.
    subprocess.Popen(command, shell=True)

# Example of a malicious input
malicious_input = "file.c; cat /etc/passwd"
run_gcov(malicious_input)