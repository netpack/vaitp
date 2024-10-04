import os

# An attacker-controlled string that simulates the malicious input
malicious_input = "__import__('os').popen('whoami').read()"

# The vulnerable part where the attacker's input is executed without sanitation
result = eval(malicious_input)

print(result)