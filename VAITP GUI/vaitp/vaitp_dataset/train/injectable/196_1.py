import sys
import os
import subprocess

# Create a malicious Python file in the current working directory
malicious_file = 'malicious.py'
with open(malicious_file, 'w') as f:
    f.write('print("Malicious code executed!")\n')

# Execute the code using subprocess.run, avoiding os.execv and issues with argv[0] manipulation
try:
    subprocess.run([sys.executable, os.path.abspath(malicious_file)] + sys.argv[1:], check=True)
except subprocess.CalledProcessError as e:
    print(f"Error executing subprocess: {e}")
finally:
  if os.path.exists(malicious_file):
    os.remove(malicious_file)