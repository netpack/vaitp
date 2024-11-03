# Hypothetical example
import json
import subprocess

def process_request(request):
    # Assume 'data' is coming from an untrusted source
    data = json.loads(request.get('data'))

    # Secure code: validate and sanitize input
    if 'command' in data:
        command = data['command']
        # Only allow specific commands
        allowed_commands = ['ls', 'pwd']  # Example of allowed commands
        if command in allowed_commands:
            subprocess.run(command, shell=True)  # Safer execution
        else:
            raise ValueError("Unauthorized command")

# Example of a malicious request
malicious_request = {
    'data': '{"command": "cat /etc/passwd"}'  # This will now be blocked
}
process_request(malicious_request)