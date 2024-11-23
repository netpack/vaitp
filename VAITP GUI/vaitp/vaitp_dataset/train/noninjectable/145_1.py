import mailcap

def vulnerable_findmatch(name, mime_type):
    # Directly using the command from mailcap without escaping
    command = mailcap.findmatch(name, mime_type)
    return command

if __name__ == "__main__":
    # Example usage with a potentially unsafe input
    user_input = "example_command"  # Assume this comes from untrusted input
    mime_type = "text/plain"
    command = vulnerable_findmatch(user_input, mime_type)
    print("Command to execute:", command)