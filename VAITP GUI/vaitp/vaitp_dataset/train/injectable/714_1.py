import bleach

def sanitize_html_input(user_input):
    # Allow only certain tags and attributes
    allowed_tags = ['p', 'b', 'i', 'u', 'strong', 'em', 'a']
    allowed_attributes = {'a': ['href', 'title']}

    # Sanitize the user input to prevent HTML injection
    sanitized_input = bleach.clean(user_input, tags=allowed_tags, attributes=allowed_attributes)
    return sanitized_input

# Example usage
user_input = '<script>alert("XSS")</script><p>This is a <a href="http://example.com" title="Example">link</a>.</p>'
safe_input = sanitize_html_input(user_input)
print(safe_input)  # Output: <p>This is a <a href="http://example.com" title="Example">link</a>.</p>