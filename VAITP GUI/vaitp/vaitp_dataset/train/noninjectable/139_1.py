# This code uses the ssl module to create a HTTPS connection to a server
# The ssl module uses the default cipher list, which includes Triple DES
# The server supports Triple DES and chooses it as the cipher for the session
# The attacker can intercept the encrypted traffic and perform a birthday attack
# to recover the plaintext data after observing about 785 GB of traffic

import ssl
import socket
host = "example.com"
port = 443
context = ssl.create_default_context() # This uses the default cipher list
sock = socket.create_connection((host, port))
ssock = context.wrap_socket(sock, server_hostname=host) # This negotiates the cipher
print(ssock.cipher()) # This shows the chosen cipher, which may be Triple DES
ssock.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n") # This sends the request
data = ssock.recv(1024) # This receives the response
print(data) # This prints the response
ssock.close()