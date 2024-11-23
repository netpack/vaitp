import os

def enter_chroot(new_root):
    # Entering chroot without disabling the crash handler
    os.chroot(new_root)
    os.chdir('/')

# Example usage
if __name__ == "__main__":
    new_root = "/path/to/new/root"
    enter_chroot(new_root)