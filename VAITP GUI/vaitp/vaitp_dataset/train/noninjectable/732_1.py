# Vulnerable code that allows execution of arbitrary system commands
import code

# Launch a Python interactive console with unrestricted access
def launch_debug_console():
    code.interact(local=globals())

if __name__ == "__main__":
    launch_debug_console()