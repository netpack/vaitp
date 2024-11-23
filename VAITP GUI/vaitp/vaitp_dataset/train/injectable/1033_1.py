import ssl
import threading

# Create an SSLContext
context = ssl.create_default_context()

# Function to load certificates
def load_certificates():
    context.load_default_certs()

# Function to call cert_store_stats and get_ca_certs simultaneously
def access_ssl_methods():
    print("Cert Store Stats:", context.cert_store_stats())
    print("CA Certs:", context.get_ca_certs())

# Create threads for simultaneous execution
load_thread = threading.Thread(target=load_certificates)
access_thread = threading.Thread(target=access_ssl_methods)

# Start the threads
load_thread.start()
access_thread.start()

# Wait for both threads to complete
load_thread.join()
access_thread.join()