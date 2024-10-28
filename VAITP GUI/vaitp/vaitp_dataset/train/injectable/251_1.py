import AWSIoTPythonSDK.MQTTLib as AWSIoTPyMQTT
import ssl

# Create a new MQTT client
mqtt_client = AWSIoTPyMQTT.AWSIoTMQTTClient("MySecureClientID")

# Configure the client to use a custom CA certificate
mqtt_client.configureEndpoint("your-iot-endpoint.amazonaws.com", 8883)

# Configure credentials with proper certificate validation
mqtt_client.configureCredentials("path/to/rootCA.pem", "path/to/private.key", "path/to/certificate.pem")

# Set the TLS version and enable hostname verification
mqtt_client.configureSSLContext(ssl.create_default_context(ssl.Purpose.CLIENT_AUTH))
mqtt_client.configureSSLContext(ssl.SSLContext(ssl.PROTOCOL_TLSv1_2))

# Connect to the AWS IoT Core
mqtt_client.connect()

# Publish a message to a topic
mqtt_client.publish("test/topic", "Hello from secure client!", 0)

# Disconnect from the AWS IoT Core
mqtt_client.disconnect()