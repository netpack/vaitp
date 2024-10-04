# This code uses the hyper-h2 library, which depends on the priority library
# It creates a HTTP/2 connection to a malicious server and sends a GET request
# The server sends priority information for every stream ID from 1 to 2**31-1
# This causes the priority tree to grow exponentially and consume all resources

import h2.connection
conn = h2.connection.H2Connection()
conn.initiate_connection()
conn.send_headers(1, [(':method', 'GET'), (':path', '/'), (':scheme', 'https'), (':authority', 'malicious.com')])
conn.receive_data(server_data) # server_data contains the malicious priority information