import os

# An attacker-controlled string that simulates the malicious input
malicious_input = "__import__('os').popen('whoami').read()"

# Instead of executing the input, just print a message or handle it safely
print("Received input:", malicious_input)

# Or, if you need to execute commands, ensure they are predefined and controlled
allowed_commands = {'whoami': 'whoami'}
command = malicious_input.split('\'')[1]  # This is a simplistic parser and not secure in real applications

if command in allowed_commands:
    result = os.popen(allowed_commands[command]).read()
    print(result)
else:
    print("Command not allowed.")