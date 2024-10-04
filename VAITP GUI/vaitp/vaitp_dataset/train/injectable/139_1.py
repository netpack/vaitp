# This code uses the ssl module to create a HTTPS connection to a server
# The ssl module uses a custom cipher list, which excludes Triple DES
# The server does not support Triple DES and chooses a different cipher for the session
# The attacker cannot intercept the encrypted traffic and perform a birthday attack
# to recover the plaintext data

import ssl
import socket
host = "example.com"
port = 443
context = ssl.create_default_context() # This creates a default SSL context
context.set_ciphers("DEFAULT:!3DES") # This sets the cipher list to exclude Triple DES
sock = socket.create_connection((host, port))
ssock = context.wrap_socket(sock, server_hostname=host) # This negotiates the cipher
print(ssock.cipher()) # This shows the chosen cipher, which is not Triple DES
ssock.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n") # This sends the request
data = ssock.recv(1024) # This receives the response
print(data) # This prints the response
ssock.close()