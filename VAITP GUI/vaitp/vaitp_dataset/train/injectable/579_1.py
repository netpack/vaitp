import bleach

# Example of sanitizing a URI input to prevent CVE-2018-3650
def sanitize_uri(input_uri):
    # Allow only specific protocols and ensure proper validation
    allowed_protocols = ['http', 'https', 'ftp']
    sanitized_uri = bleach.clean(input_uri, tags=[], attributes={}, styles=[], strip=True)

    # Validate the protocol
    if any(sanitized_uri.startswith(protocol + '://') for protocol in allowed_protocols):
        return sanitized_uri
    else:
        raise ValueError("Invalid URI: Only HTTP, HTTPS, and FTP protocols are allowed.")

# Example usage
try:
    user_input = "javascript:alert('XSS')"  # Example of malicious input
    safe_uri = sanitize_uri(user_input)
    print("Sanitized URI:", safe_uri)
except ValueError as e:
    print(e)