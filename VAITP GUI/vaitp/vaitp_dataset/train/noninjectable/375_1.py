import gnupg

gpg = gnupg.GPG()

# User input is not sanitized
user_input = "somefile.txt; cat /etc/passwd"  # Malicious input
result = gpg.encrypt_file(user_input, recipients=['recipient@example.com'])

if result.ok:
    print("File encrypted successfully.")
else:
    print("Error:", result.stderr)