import subprocess
import json

def handle_tool_calls(tool_calls):
    for tool_call in tool_calls:
        function_name = tool_call.get("function", {}).get("name")
        arguments = tool_call.get("function", {}).get("arguments")
        if function_name == "run_shell_command":
            if arguments:
                try:
                    arguments_dict = json.loads(arguments)
                    command = arguments_dict.get("command")
                    if command:
                      process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                      stdout, stderr = process.communicate()
                      return_code = process.returncode
                      return {
                         "stdout": stdout.decode("utf-8"),
                         "stderr": stderr.decode("utf-8"),
                         "return_code": return_code
                      }
                except json.JSONDecodeError:
                     return "Invalid JSON arguments"
    return "No tool calls"

if __name__ == '__main__':
  # Example usage with a crafted tool call
  tool_call_example = [
    {
      "id": "1",
      "function": {
        "name": "run_shell_command",
        "arguments": '{"command": "ls -la && whoami"}'
       }
    }
  ]
  
  result = handle_tool_calls(tool_call_example)
  print(result)