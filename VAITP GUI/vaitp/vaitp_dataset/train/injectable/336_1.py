from pyparsing import Word, alphas, alphanums

def handle_authenticate_header(header):
    # Improved parsing using pyparsing
    try:
        # Define a simple parser for the authentication scheme
        scheme = Word(alphas)
        auth_param = Word(alphanums + '._-')
        parser = scheme + auth_param

        # Parse the header safely
        result = parser.parseString(header)
        print("Parsed header:", result)

    except Exception as e:
        print("Failed to parse header:", e)

# Simulating receiving a header
header = "WWW-Authenticate: " + "\xa0" * 1000  # Example of a malicious header
handle_authenticate_header(header)