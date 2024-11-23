def handle_third_party_invite(event, user_ip):
    """Handle third-party invite events without IP validation."""
    # Directly process the invite event without checking the IP address
    # (This is where the vulnerability exists)
    # Example of making a request to a user-provided domain
    request_url = event['invite_url']  # URL provided by the user
    response = make_request_to_url(request_url, event['request_body'])
    
    # Process the response from the request
    print("Invite processed with response:", response)

def make_request_to_url(url, body):
    """Simulate making a request to the given URL with the provided body."""
    # This function would make an actual HTTP request
    # (Implementation omitted for brevity)
    return "Response from {}".format(url)