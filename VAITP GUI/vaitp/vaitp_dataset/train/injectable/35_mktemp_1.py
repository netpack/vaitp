import tempfile

# Create a secure temporary file using NamedTemporaryFile
with tempfile.NamedTemporaryFile(delete=False) as temp_file:
    temp_file.write(b"This is sensitive data.")
    temp_file.seek(0)

    # Simulate a legitimate operation with the temporary file
    with open(temp_file.name, 'rb') as f:
        data = f.read()
        print("Legitimate Operation Output: ", data)

# Attempting to access the temporary file from attacker code
attacker_code = """
with open('{}', 'rb') as f:
    data = f.read()
    print("Attacker Code Output: ", data)
""".format(temp_file.name)

exec(attacker_code)
