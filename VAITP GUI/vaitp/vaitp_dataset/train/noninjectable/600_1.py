def unsafe_script_invoke(script):
    # Directly executing user-supplied script
    exec(script)

# Example usage
user_input_script = "__import__('os').system('ls')"  # Arbitrary code execution
unsafe_script_invoke(user_input_script)