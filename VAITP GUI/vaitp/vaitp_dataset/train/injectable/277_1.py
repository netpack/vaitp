# Safe version of the d8s-ip-addresses package without the backdoor

class SafeIPAddressManager:
    def __init__(self):
        self.ip_addresses = []

    def add_ip_address(self, ip):
        if self.validate_ip(ip):
            self.ip_addresses.append(ip)
        else:
            raise ValueError("Invalid IP address format")

    def validate_ip(self, ip):
        # Basic IP address validation logic
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or not (0 <= int(part) <= 255):
                return False
        return True

    def get_ip_addresses(self):
        return self.ip_addresses

# Example usage
manager = SafeIPAddressManager()
manager.add_ip_address("192.168.1.1")
print(manager.get_ip_addresses())