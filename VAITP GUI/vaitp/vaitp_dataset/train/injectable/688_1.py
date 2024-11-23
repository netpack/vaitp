import IPython.utils.terminal

def safe_set_term_title(title):
    # Ensure the title is safe and does not contain any shell metacharacters
    if any(char in title for char in [';', '&', '|', '>', '<', '$', '`']):
        raise ValueError("Unsafe title provided")
    IPython.utils.terminal.set_term_title(title)

# Example usage
try:
    safe_set_term_title("My Safe Title")
except ValueError as e:
    print(e)