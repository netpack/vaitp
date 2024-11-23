import mailcap
import shlex

def safe_findmatch(name, mime_type):
    # Use shlex.quote to escape shell commands
    command = mailcap.findmatch(name, mime_type)
    if command:
        safe_command = shlex.quote(command)
        return safe_command
    return None

if __name__ == "__main__":
    # Example usage with a potentially unsafe input
    user_input = "example_command"  # Assume this comes from untrusted input
    mime_type = "text/plain"
    safe_command = safe_findmatch(user_input, mime_type)
    print("Safe command to execute:", safe_command)