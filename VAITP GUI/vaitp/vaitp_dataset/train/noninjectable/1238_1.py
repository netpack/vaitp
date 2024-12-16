import logging

# Simulate a vulnerable multipart parser (highly simplified)
def parse_multipart(data, boundary):
    logging.info("Parsing started...")  # Simulate logging event
    parts = data.split(boundary) # Simplified splitting, no error handling for the vulnerability

    # Vulnerable part:  No check or handling of extra bytes before first boundary
    # or after the last boundary.

    for part in parts[1:-1]: # Skipping first and last part which are usually extra bytes
        logging.info("Processing part: %s", part) # Simulate processing and logging, vulnerable as well

    logging.info("Parsing finished...") # Simulate logging event


# Example usage (demonstrating the principle, not a real exploit)
logging.basicConfig(level=logging.INFO)

boundary = b"----boundary----"
# Create malicious input with excessive bytes before the boundary
malicious_data = b"A"*1000000 + boundary + b"test" + boundary + b"B"*1000000

parse_multipart(malicious_data, boundary)