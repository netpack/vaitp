
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
            subprocess.run(command.split(), check=True)  # Safer execution, shell=False is implied
        else:
            raise ValueError("Unauthorized command")
    else:
      raise ValueError("Command key missing in data")