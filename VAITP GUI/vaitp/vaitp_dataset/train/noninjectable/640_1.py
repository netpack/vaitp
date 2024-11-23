def unsafe_execute(command):
    # Directly using eval on user input, leading to potential code execution
    return eval(command)

# Example of how the API might call the unsafe_execute function
def api_call(command):
    try:
        result = unsafe_execute(command)
        return {"status": "success", "result": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Example usage
response = api_call('2 + 2')  # Arbitrary code execution
print(response)

response = api_call('__import__("os").system("ls")')  # Potentially dangerous command
print(response)