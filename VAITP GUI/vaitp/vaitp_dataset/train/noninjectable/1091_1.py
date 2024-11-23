def run_script(script):
    # Directly executing the script without validation
    exec(script)

# Example usage
malicious_script = "__import__('os').system('whoami')"  # Malicious script example
run_script(malicious_script)  # This would execute the malicious command