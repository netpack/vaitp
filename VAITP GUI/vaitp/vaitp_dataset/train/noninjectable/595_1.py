import json
import os

def run_code(code):
    # Directly executing the code which can be a security risk
    exec(code)

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
        "content": "os.system('echo Hello, World!')"
    }
})

# Running the request
response = handle_request(request)
print(response)