import tempfile

# Define a directory for temporary files (replace with your desired directory)
temp_dir = "/tmp"

try:
    # Create a secure temporary file in the specified directory
    with tempfile.NamedTemporaryFile(dir=temp_dir, prefix="prefix_", delete=False) as temp_file:
        temp_filename = temp_file.name

        # Simulate writing sensitive data to the temporary file
        temp_file.write(b"This is sensitive data.")

        # Attempt to access the temporary file from attacker code
        attacker_code = f"""
        with open('{temp_filename}', 'rb') as f:
            data = f.read()
            print("Attacker Code Output: ", data)
        """

        exec(attacker_code)

except Exception as e:
    print("An error occurred:", str(e))

