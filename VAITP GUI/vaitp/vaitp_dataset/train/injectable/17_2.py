# Import the encodings.idna module
import encodings.idna

# Define a malicious hostname
# This hostname has 10000 dots
hostname = "." * 10000

# Try to decode the hostname using the encodings.idna module
# This will not trigger the vulnerability in the idna.py module
# The decode function will use a linear algorithm
# This will result in a fast and safe decoding
encodings.idna.decode(hostname)