# Vulnerable version of the d8s-ip-addresses package with the backdoor

# This version incorrectly imports the democritus-csv package, which contains the backdoor.
import democritus_csv  # Vulnerable import

def read_ip_addresses(file_path):
    ip_addresses = []
    # Using the vulnerable democritus_csv package to read IP addresses
    with democritus_csv.open(file_path, mode='r') as file:
        for row in democritus_csv.reader(file):
            ip_addresses.append(row[0])  # Assuming each row contains an IP address
    return ip_addresses

# Example usage
# ip_list = read_ip_addresses('ip_addresses.csv')