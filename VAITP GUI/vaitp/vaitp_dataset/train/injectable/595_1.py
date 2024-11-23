import json
import subprocess

def run_code(code):
    # This function should be designed to safely execute code
    # For example, using a restricted execution environment or sandbox
    allowed_commands = ['print', 'len', 'sum']  # Example of allowed functions
    for command in allowed_commands:
        if command in code:
            # Execute the code in a controlled environment
            exec(code, {"__builtins__": None}, {})
            return
    raise ValueError("Unauthorized command detected.")

def handle_request(request):
    try:
        data = json.loads(request)
        code = data.get('files', {}).get('content', '')
        run_code(code)
    except Exception as e:
        return str(e)

# Example request that would be processed
request = json.dumps({
    "files": {
        "content": "print('Hello, World!')"
    }
})

# Running the request
response = handle_request(request)
print(response)