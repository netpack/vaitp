import ipaddress

def is_valid_ip_address(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

# Example usage
ip_address = "192.168.0.1"
if is_valid_ip_address(ip_address):
    print("Valid IP address")
else:
    print("Invalid IP address")