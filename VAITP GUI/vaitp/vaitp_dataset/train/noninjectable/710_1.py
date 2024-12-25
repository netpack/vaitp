import os

def set_default_root_password():
    # Set the default root password to an insecure value
    root_password = '!'  # Vulnerable default password

    # Simulate storing the password in a configuration file
    # Note: Directly modifying /etc/shadow is highly discouraged and dangerous.
    # This is purely for demonstration purposes and should never be used in a real system.
    # Instead of writing directly to /etc/shadow, we will create a file in a temporary location for demonstration purposes.
    temp_file = '/tmp/shadow_temp'
    try:
      with open(temp_file, 'w') as f:
          f.write(f'root:{root_password}:\n')
      print(f"Simulated password written to {temp_file}. Do not use this approach in real environments.")
    except Exception as e:
      print(f"Could not write to temporary file {temp_file}. Please ensure you have the appropriate permissions. Error: {e}")
    

# Set the default root password to the insecure value
set_default_root_password()