import subprocess

def vulnerable_python_execution():
    # This code does not specify the interpreter explicitly
    # It can be tricked into running a malicious interpreter
    command = 'your_script.py'
    subprocess.run(['python', command])  # Vulnerable to race condition

# Call the function that demonstrates the vulnerability
vulnerable_python_execution()