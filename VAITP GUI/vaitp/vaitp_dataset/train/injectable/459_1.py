class UnauthorizedAccessError(Exception):
    """Exception raised for unauthorized access attempts."""
    pass

def handle_request(request):
    if not is_authenticated(request):
        raise UnauthorizedAccessError("User  is not authenticated")
    
    process_request(request)

def is_authenticated(request):
    # Simulate an authentication check (this would be more complex in a real application)
    # For example, check if a token is present and valid
    return 'auth_token' in request  # Simplified example

def process_request(request):
    # Simulate processing the request
    print(f"Processing request: {request}")

# Example usage with authentication
request_with_auth = {"data": "Sample request data", "auth_token": "valid_token"}
handle_request(request_with_auth)

# Example usage without authentication
request_without_auth = {"data": "Sample request data"}
try:
    handle_request(request_without_auth)
except UnauthorizedAccessError as e:
    print(e)  # Output: User is not authenticated