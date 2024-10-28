import splunklib.client as client

# Connect to Splunk with verified SSL certificate
service = client.connect(
    host='splunk-server.example.com',
    port=8089,
    username='admin',
    password='your_password',
    scheme='https',
    verify=True  # Enable SSL certificate verification
)

# Now you can interact with Splunk securely
print(service.info)