import splunklib.client as client

# Connect to Splunk with unverified SSL certificate
service = client.connect(
    host='splunk-server.example.com',
    port=8089,
    username='admin',
    password='your_password',
    scheme='https',
    verify=False  # This disables SSL certificate verification
)

# Now you can interact with Splunk
print(service.info)