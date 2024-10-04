from os import path

# CVE-2023-41105 demonstration
# Suppose an application uses normpath to normalize paths received from user input
# A malicious user could exploit the vulnerability by injecting a null byte
user_input_path = "/legitimate/path\0/../../../../etc/passwd"

# The application attempts to normalize the path
normalized_path = path.normpath(user_input_path)

# The expectation might be that normpath would handle or reject the path securely
# However, due to the vulnerability, the path is truncated at the null byte, potentially leading to security issues
print("Normalized Path:", normalized_path)