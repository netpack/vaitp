# Vulnerable code snippet demonstrating the infinite loop issue
def vulnerable_parse_content_stream(stream):
    while True:
        peek = stream.peek(1)
        if peek not in (b"\r", b"\n"):
            # Process the content
            pass  # This represents processing logic
        else:
            break

# Fixed code snippet
def fixed_parse_content_stream(stream):
    while True:
        peek = stream.peek(1)
        if peek not in (b"\r", b"\n", b""):
            # Process the content
            pass  # This represents processing logic
        else:
            break