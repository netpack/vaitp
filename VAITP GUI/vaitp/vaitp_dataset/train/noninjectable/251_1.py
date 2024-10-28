import AWSIoTPythonSDK.MQTTLib as AWSIoTPyMQTT

# Create a new MQTT client
mqtt_client = AWSIoTPyMQTT.AWSIoTMQTTClient("MyClientID")

# Configure the client to use a custom CA certificate
mqtt_client.configureEndpoint("your-iot-endpoint.amazonaws.com", 8883)
mqtt_client.configureCredentials("path/to/rootCA.pem", "path/to/private.key", "path/to/certificate.pem")

# Connect to the AWS IoT Core
mqtt_client.connect()

# Publish a message to a topic
mqtt_client.publish("test/topic", "Hello from vulnerable client!", 0)

# Disconnect from the AWS IoT Core
mqtt_client.disconnect()