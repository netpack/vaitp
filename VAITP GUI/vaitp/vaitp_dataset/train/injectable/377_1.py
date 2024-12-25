# Hypothetical example
import json
import subprocess

def process_request(request):
    # Assume 'data' is coming from an untrusted source
    try:
        data = json.loads(request.get('data', '{}'))
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON format")

    # Secure code: validate and sanitize input
    if 'command' in data:
        command = data['command']
        # Only allow specific commands
        allowed_commands = ['ls', 'pwd']  # Example of allowed commands
        if command in allowed_commands:
            subprocess.run(command, shell=False, check=True)  # Safer execution, shell=False is important
        else:
            raise ValueError("Unauthorized command")
    else:
      raise ValueError("Command key missing in data")

# Example of a malicious request
malicious_request = {
    'data': '{"command": "cat /etc/passwd"}'  # This will now be blocked
}
try:
    process_request(malicious_request)
except ValueError as e:
    print(f"Error: {e}")

#Example of a valid request
valid_request = {
    'data': '{"command": "ls"}'
}
try:
    process_request(valid_request)
except ValueError as e:
    print(f"Error: {e}")