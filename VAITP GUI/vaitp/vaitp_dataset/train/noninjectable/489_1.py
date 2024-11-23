import sys

# Vulnerable code: The current working directory is included in sys.path
# This allows for the execution of a Trojan horse Python file if it exists in the current directory

# Assume a malicious script 'malicious.py' exists in the current working directory
# This could be executed unintentionally if the current directory is in sys.path
import malicious  # This could be a Trojan horse script

# Continue with the rest of the application logic