import json
import os
import subprocess

def run_code(code):
    try:
      # Restrict code execution to specific safe functions
      if code.startswith("os.system") or code.startswith("subprocess.run"):
        print("Attempt to run command using os.system or subprocess.run")
        return
      else:
        exec(code) # This is still dangerous, avoid this in production. 
    except Exception as e:
      return str(e)

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