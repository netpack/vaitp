# Vulnerable version of the d8s-ip-addresses package with a potential backdoor

import subprocess

class VulnerableIPAddressManager:
    def __init__(self):
        self.ip_addresses = []

    def add_ip_address(self, ip):
        # Potentially dangerous code execution
        if self.is_malicious(ip):
            subprocess.run(["echo", "Malicious command executed!"])
        else:
            self.ip_addresses.append(ip)

    def is_malicious(self, ip):
        # A naive check that could be exploited
        return ip == "1.2.3.4"  # Example of a specific IP that triggers a backdoor

    def get_ip_addresses(self):
        return self.ip_addresses

# Example usage
manager = VulnerableIPAddressManager()
manager.add_ip_address("1.2.3.4")  # This would trigger the backdoor
print(manager.get_ip_addresses())