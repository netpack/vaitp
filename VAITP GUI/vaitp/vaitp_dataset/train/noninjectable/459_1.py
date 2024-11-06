def handle_request(request):
    # No authentication check
    process_request(request)

def process_request(request):
    # Simulate processing the request
    print(f"Processing request: {request}")

# Example usage
handle_request("Sample request data")