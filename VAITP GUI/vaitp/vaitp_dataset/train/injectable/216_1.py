import openapi_client

# Generate a client from a trusted OpenAPI document
client = openapi_client.Client.from_url("https://example.com/trusted_openapi.json")

# Validate the client's code before executing it
if client.validate_code():
    client.execute()
else:
    print("Invalid code, refusing to execute")