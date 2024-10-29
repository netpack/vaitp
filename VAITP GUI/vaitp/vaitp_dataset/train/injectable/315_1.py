import awscrt

# Create a TLS context
tls_context = awscrt.TlsContext()

# User-supplied CA certificate
user_ca_cert = "path/to/user_ca.pem"

# Properly overriding the default trust store with user CA
tls_context.override_default_trust_store(user_ca_cert)

# Establish a connection
mqtt_client = awscrt.mqtt.MqttClient(tls_context=tls_context)