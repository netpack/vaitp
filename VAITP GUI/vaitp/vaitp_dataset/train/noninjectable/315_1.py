import awscrt.io
import awscrt.mqtt

# Create a TLS context
tls_options = awscrt.io.TlsContextOptions()
tls_context = awscrt.io.ClientTlsContext(tls_options)

# User-supplied CA certificate
user_ca_cert = "path/to/user_ca.pem"

# Properly add user CA to the TLS context options before creating the context
tls_options.add_ca_from_path(user_ca_cert)



# Establish a connection
mqtt_client = awscrt.mqtt.Client(event_loop_group=awscrt.io.EventLoopGroup(1), tls_context=tls_context)