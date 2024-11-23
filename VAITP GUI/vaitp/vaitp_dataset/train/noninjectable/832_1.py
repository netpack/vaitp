def __parse_content_stream(stream):
    while True:
        peek = stream.peek(1)
        if peek not in (b"\r", b"\n"):
            # Process the content
            pass  # This represents processing logic
        else:
            break