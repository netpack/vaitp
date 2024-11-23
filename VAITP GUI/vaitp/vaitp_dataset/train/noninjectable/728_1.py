from django.core.validators import URLValidator

# Example of using URLValidator which may allow leading zeros in IP addresses
url_validator = URLValidator()

# Example of potentially vulnerable IP addresses
try:
    url_validator("http://192.168.01.1")  # Leading zero in the octet
    print("Valid URL with leading zero in IP")
except Exception as e:
    print(e)

try:
    url_validator("http://10.0.0.1")  # Valid
    print("Valid URL")
except Exception as e:
    print(e)