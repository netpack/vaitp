class VulnerableContext:
    def __init__(self):
        self.secret_data = "Sensitive information"

def vulnerable_format(format_string, mapping):
    # Using str.format_map which is unsafe
    return format_string.format_map(mapping)

# Example usage
context = VulnerableContext()
user_input = "{secret_data}"  # Untrusted input
result = vulnerable_format(user_input, vars(context))
print(result)  # This will output "Sensitive information"