def handle_authenticate_header(header):
    # Vulnerable code that directly processes the header
    if header.startswith("Basic"):
        # Process Basic authentication
        pass
    elif header.startswith("Bearer"):
        # Process Bearer token
        pass
    # Potentially vulnerable to long sequences in the header
    # This could lead to excessive CPU usage if exploited
    print("Processing header:", header)

# Simulating receiving a header
header = "WWW-Authenticate: " + "\xa0" * 1000  # Example of a malicious header
handle_authenticate_header(header)