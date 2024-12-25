# Hypothetical example
import json

def process_request(request):
    # Assume 'data' is coming from an untrusted source
    try:
        data = json.loads(request.get('data'))
    except (json.JSONDecodeError, TypeError):
        print("Invalid JSON or missing 'data' in request.")
        return

    # Vulnerable code: executing a command based on user input
    if 'command' in data:
        print("Command execution is disabled for security reasons.")
        # Instead of executing, log and alert about the malicious attempt
        print(f"Suspicious command attempt: {data['command']}")
        #Or you could implement sanitization/filtering logic here, but avoiding command execution is best.

# Example of a malicious request
malicious_request = {
    'data': '{"command": "__import__(\'os\').system(\'cat  /etc/passwd\')"}'
}
process_request(malicious_request)