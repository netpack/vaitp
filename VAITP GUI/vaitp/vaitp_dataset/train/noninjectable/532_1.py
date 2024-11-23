from pwntools import shellcraft

# Vulnerable code that uses shellcraft with user input directly
def generate_shellcode(user_input):
    # This allows for Server-Side Template Injection (SSTI)
    shellcode_template = f"""
    {shellcraft.sh()}
    {user_input}
    """
    return shellcode_template

# Example usage with potentially unsafe user input
user_input = "{{ config }}; echo 'Injected Command'"
output = generate_shellcode(user_input)
print(output)