import ipaddress

def is_ip_allowed(ip, allowed_ranges):
    """Check if the given IP is within the allowed ranges."""
    ip_obj = ipaddress.ip_address(ip)
    for ip_range in allowed_ranges:
        if ip_obj in ipaddress.ip_network(ip_range):
            return True
    return False

def handle_third_party_invite(event, user_ip):
    """Handle third-party invite events with IP validation."""
    # Example of allowed external IP ranges
    allowed_ip_ranges = [
        '192.0.2.0/24',  # Example external range
        '203.0.113.0/24' # Another example external range
    ]

    if not is_ip_allowed(user_ip, allowed_ip_ranges):
        raise ValueError("IP address not allowed for this request.")

    # Proceed with handling the invite event
    # (Code to process the invite would go here)
    print("Invite processed successfully.")