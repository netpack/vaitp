import bleach

# Example of insufficient URI sanitization that represents the vulnerability
def unsafe_sanitize_uri(input_uri):
    # No proper validation of allowed protocols
    sanitized_uri = bleach.clean(input_uri, tags=[], attributes={}, styles=[], strip=True)
    return sanitized_uri  # Returns potentially unsafe URI

# Example usage
user_input = "javascript:alert('XSS')"  # Example of malicious input
unsafe_uri = unsafe_sanitize_uri(user_input)
print("Sanitized URI:", unsafe_uri)  # This could output a dangerous URI