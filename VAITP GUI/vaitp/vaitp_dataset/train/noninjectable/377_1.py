# Hypothetical example
import json

def process_request(request):
    # Assume 'data' is coming from an untrusted source
    data = json.loads(request.get('data'))

    # Vulnerable code: executing a command based on user input
    if 'command' in data:
        exec(data['command'])  # This is dangerous!

# Example of a malicious request
malicious_request = {
    'data': '{"command": "__import__(\'os\').system(\'cat  /etc/passwd\')"}'
}
process_request(malicious_request)