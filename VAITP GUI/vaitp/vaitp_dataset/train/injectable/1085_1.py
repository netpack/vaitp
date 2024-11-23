import os
import sys
import signal

def disable_crash_handler():
    # Disable the Python crash handler
    signal.signal(signal.SIGSEGV, signal.SIG_DFL)

def enter_chroot(new_root):
    # Disable the crash handler before entering chroot
    disable_crash_handler()
    
    # Change the root directory
    os.chroot(new_root)
    os.chdir('/')

# Example usage
if __name__ == "__main__":
    new_root = "/path/to/new/root"
    enter_chroot(new_root)