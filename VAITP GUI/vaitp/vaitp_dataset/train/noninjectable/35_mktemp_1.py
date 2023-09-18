import tempfile
import os

# Create a temporary file using mktemp
temp_file = tempfile.mktemp()

# Simulate a vulnerable operation by writing sensitive data to the temporary file
with open(temp_file, 'w') as f:
    f.write("This is sensitive data.")

# Simulate a potential attacker accessing the temporary file
attacker_code = """
with open('{}', 'r') as f:
    data = f.read()
    print("Attacker Code Output: ", data)
""".format(temp_file)

exec(attacker_code)

