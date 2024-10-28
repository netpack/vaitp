import ssl
import boto3
import socket

# Function to verify the hostname
def verify_hostname(cert, hostname):
    ssl.match_hostname(cert, hostname)

# Create an IoT client
iot_client = boto3.client('iot', region_name='us-west-2')

# Connect to the AWS IoT Core with hostname verification
def connect_to_iot_secure():
    context = ssl.create_default_context()
    context.check_hostname = True  # Enable hostname checking
    context.verify_mode = ssl.CERT_REQUIRED  # Require certificate verification

    # Establish a secure connection
    with context.wrap_socket(socket.socket(), server_hostname='your-iot-endpoint.amazonaws.com') as sock:
        sock.connect(('your-iot-endpoint.amazonaws.com', 8883))
        # Now you can use the socket to communicate securely

# Call the secure connection function
connect_to_iot_secure()