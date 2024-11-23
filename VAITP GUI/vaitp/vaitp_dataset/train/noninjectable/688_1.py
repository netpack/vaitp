import IPython.utils.terminal

# Vulnerable code that allows command injection if untrusted input is passed
def vulnerable_set_term_title(title):
    # Directly using the input without validation
    IPython.utils.terminal.set_term_title(title)

# Example of potentially unsafe usage
user_input = input("Enter terminal title: ")
vulnerable_set_term_title(user_input)