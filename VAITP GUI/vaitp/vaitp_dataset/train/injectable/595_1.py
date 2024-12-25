import json
import subprocess

def run_code(code):
    # This function should be designed to safely execute code
    # For example, using a restricted execution environment or sandbox
    allowed_commands = ['print', 'len', 'sum']  # Example of allowed functions
    
    # Split the code into lines and check each line for allowed commands
    lines = code.strip().split("\n")
    for line in lines:
        if line.strip() and not any(cmd in line for cmd in allowed_commands) and not line.strip().startswith("#"):
           raise ValueError("Unauthorized command detected.")

    # Execute the code in a controlled environment
    try:
        exec(code, {"__builtins__": None}, {})
        return
    except Exception as e:
        raise ValueError(f"Execution error: {e}")

def handle_request(request):
    try:
        data = json.loads(request)
        code = data.get('files', {}).get('content', '')
        run_code(code)
        return "Code executed successfully"
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