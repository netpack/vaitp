# Vulnerable code using eval (demonstrating the issue)
user_input = "__import__('os').system('ls')"  # Example of malicious input
result = eval(user_input)  # This can execute arbitrary code