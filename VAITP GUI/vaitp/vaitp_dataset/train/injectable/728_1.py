import re
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator

def validate_ip_address(ip):
    # Regex to match valid IPv4 addresses without leading zeros
    ipv4_pattern = re.compile(r'^(?!0)([1-9]\d{0,2}|0)(\.(?!0)([1-9]\d{0,2}|0)){3}$')
    
    if not ipv4_pattern.match(ip):
        raise ValidationError(f"{ip} is not a valid IPv4 address.")
    
    # If additional validation is needed, you can add it here

# Example usage
try:
    validate_ip_address("192.168.1.1")  # Valid
    validate_ip_address("192.168.01.1")  # Invalid
except ValidationError as e:
    print(e)