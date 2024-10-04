# Example function that takes user input to create a config file
def create_config(user_input):
    config_content = f"[settings]\nuser_setting={user_input}"
    with open("vulnerable_config.ini", "w") as config_file:
        config_file.write(config_content)

# Function that uses the config file to run a system command
def run_with_config():
    import configparser
    config = configparser.ConfigParser()
    config.read("vulnerable_config.ini")
    user_setting = config['settings']['user_setting']
    
    # A vulnerable system command execution based on user input
    import os
    os.system(f"echo {user_setting}")  # Vulnerable to command injection

# Hypothetical user input that could lead to exploitation
malicious_input = "dummy; cat /etc/passwd #"

# Running the hypothetical vulnerable flow
create_config(malicious_input)
run_with_config()