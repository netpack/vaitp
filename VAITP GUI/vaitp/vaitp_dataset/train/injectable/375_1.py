import gnupg

gpg = gnupg.GPG()

# Assume we have a function to sanitize input
def sanitize_input(file_name):
    # Basic sanitization example
    if not file_name.isalnum():  # Only allow alphanumeric filenames
        raise ValueError("Invalid filename.")
    return file_name

try:
    user_input = "somefile.txt; cat /etc/passwd"  # Malicious input
    sanitized_input = sanitize_input(user_input)
    
    result = gpg.encrypt_file(sanitized_input, recipients=['recipient@example.com'])

    if result.ok:
        print("File encrypted successfully.")
    else:
        print("Error:", result.stderr)

except ValueError as e:
    print("Input error:", e)
except Exception as e:
    print("An error occurred:", e)