import os

# Define a directory for temporary files (replace with your desired directory)
temp_dir = "/tmp"

# Generate a temporary filename using tempnam (vulnerable)
temp_filename = os.tempnam(temp_dir, "prefix_")

# Simulate writing sensitive data to the temporary file
with open(temp_filename, 'w') as f:
    f.write("This is sensitive data.")

# Attempt to access the temporary file from attacker code
attacker_code = f"""
with open('{temp_filename}', 'r') as f:
    data = f.read()
    print("Attacker Code Output: ", data)
"""

exec(attacker_code)

