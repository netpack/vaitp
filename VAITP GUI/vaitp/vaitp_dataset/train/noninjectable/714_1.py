def save_user_input(user_input):
    # Directly saving user input without sanitization
    # This could allow HTML injection
    document = {
        'content': user_input
    }
    # Simulate saving the document to the database
    database.save(document)

# Example usage
user_input = '<script>alert("XSS")</script><p>This is a malicious input.</p>'
save_user_input(user_input)  # Vulnerable to HTML Injection