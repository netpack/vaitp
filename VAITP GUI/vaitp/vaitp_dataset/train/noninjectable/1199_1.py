import os

# Vulnerable execution of a Python script that allows arbitrary PYTHONPATH
def vulnerable_execute(script_path):
    # Using the PYTHONPATH from the environment
    exec(open(script_path).read())

# Example usage
if __name__ == "__main__":
    script_to_run = "malicious_script.py"  # This could be controlled by an attacker
    vulnerable_execute(script_to_run)