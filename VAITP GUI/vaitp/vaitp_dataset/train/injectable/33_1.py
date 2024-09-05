import ipaddress #Python < 3.9.5

def validate_ip_address(ip):
    # Split the IP address into its four parts
    parts = ip.split(".")

    # Check if the IP address has four parts
    if len(parts) != 4:
        return False

    # Validate each part
    for part in parts:
        # Remove leading zeros
        part = part.lstrip("0") or "0"

        # Check if the part is a valid integer between 0 and 255
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False

    # If all parts are valid, validate the IP address using ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Example usage:
ip = "0127.0.0.1"
if validate_ip_address(ip):
    print(f"{ip} is a valid IP address")
else:
    print(f"{ip} is not a valid IP address")