import subprocess

def run_command_with_secret(secret):
    try:
        # Vulnerable code: passing the secret directly as an argument
        result = subprocess.run(
            ['your_command', 'arg1', 'arg2', secret],  # Secret passed as an argument
            check=True,
            capture_output=True,
            text=True
        )
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e.stderr}")

# Example usage
run_command_with_secret('my_secret_value')