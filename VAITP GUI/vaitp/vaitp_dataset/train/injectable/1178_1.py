from waitress import serve

# Disable request lookahead to mitigate the vulnerability
serve(app, channel_request_lookahead=0)