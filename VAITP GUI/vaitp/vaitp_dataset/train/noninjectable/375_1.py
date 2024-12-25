import gnupg
import os

gpg = gnupg.GPG()

# User input should not be directly used as a file path
user_input = "somefile.txt; cat /etc/passwd"  # Malicious input
# Create a dummy file to be encrypted
with open("temp_file.txt", "w") as f:
    f.write("This is some content to be encrypted.")

# Ensure that the file exists before attempting to encrypt it.
if os.path.exists("temp_file.txt"):
    result = gpg.encrypt_file("temp_file.txt", recipients=['recipient@example.com'])

    if result.ok:
        print("File encrypted successfully.")
    else:
        print("Error:", result.stderr)
    os.remove("temp_file.txt") # Clean up the temporary file.
else:
    print("Error: File does not exist.")