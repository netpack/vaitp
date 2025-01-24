import awscrt.io
import awscrt.mqtt
import os

# Create a TLS context
tls_options = awscrt.io.TlsContextOptions()

# User-supplied CA certificate
user_ca_cert = "path/to/user_ca.pem"

# Check if the provided path is valid and exists
if not user_ca_cert or not os.path.exists(user_ca_cert):
    raise ValueError("Invalid path to CA certificate provided.")

# Properly overriding the default trust store with user CA
tls_options.override_default_trust_store_from_path(None, user_ca_cert)

tls_context = awscrt.io.TlsContext(tls_options)


# Establish a connection
mqtt_client = awscrt.mqtt.Client(event_loop_group=awscrt.io.EventLoopGroup(1), tls_context=tls_context)
