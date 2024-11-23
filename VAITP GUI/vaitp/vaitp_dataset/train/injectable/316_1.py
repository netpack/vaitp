# Fixed version of the vulnerable code that avoids importing the malicious package

# Instead of importing the democritus-networking package, we will use a safe alternative
import socket

def get_ip_address(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.error as e:
        print(f"Error resolving hostname: {e}")
        return None

# Example usage
if __name__ == "__main__":
    hostname = "example.com"
    ip = get_ip_address(hostname)
    if ip:
        print(f"The IP address of {hostname} is {ip}")