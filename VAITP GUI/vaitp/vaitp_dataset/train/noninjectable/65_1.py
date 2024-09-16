import ipaddress

def is_valid_ip_address(ip_address):
    try:
        ip_address_obj = ipaddress.ip_address(ip_address)
        hash_value = hash(ip_address_obj)
        return True
    except ValueError:
        return False

# Example usage
ip_address = "192.168.0.1"
if is_valid_ip_address(ip_address):
    print("Valid IP address")
else:
    print("Invalid IP address")