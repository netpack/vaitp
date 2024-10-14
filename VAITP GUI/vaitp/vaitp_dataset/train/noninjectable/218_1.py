from openapi_python_client import generate_client

# Using the openapi-python-client package with malicious input
malicious_input = "../../../../../../../../etc/passwd"
generate_client(malicious_input)