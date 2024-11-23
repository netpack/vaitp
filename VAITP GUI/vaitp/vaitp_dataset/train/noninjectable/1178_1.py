from waitress import serve

# Enable request lookahead to demonstrate the vulnerability
serve(app, channel_request_lookahead=1)