import marshal

user_input = input("Enter marshaled Python code to execute: ")

try:
    # This script deserializes and executes user-input marshaled code using marshal.loads
    code_object = marshal.loads(user_input.encode('latin1'))
    exec(code_object)
except Exception as e:
    print("An error occurred:", str(e))
