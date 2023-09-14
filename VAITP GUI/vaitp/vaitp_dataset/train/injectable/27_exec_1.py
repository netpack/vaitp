import sys, builtins

def secure_exec(code):
    # Define a whitelist of safe built-in functions and modules
    safe_builtins = {
        'print': print,
        'input': input,
    }

    safe_globals = {
        '__builtins__': safe_builtins,
    }

    try:
        # Execute user-input code in a restricted environment
        exec(code, safe_globals)
    except Exception as e:
        print("An error occurred:", str(e))

while True:
    user_input = input("Enter Python code to execute (or 'exit' to quit): ")
    if user_input.lower() == 'exit':
        break

    secure_exec(user_input)


