from flask import request

def save_config():
    key = request.args.get('key')
    
    # Vulnerable code: using eval on user input
    eval_result = eval(key)  # This allows arbitrary code execution

    # Process the eval result as needed
    return {"result": eval_result}