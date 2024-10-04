# This code creates a directory with a safe name and location
import os
import threading

def create_dir(name):
    os.umask(0o077) # Set the umask to 0o077 (only owner can read, write, and execute)
    os.makedirs(name, exist_ok=True) # This call does not trigger the race condition

# Create two threads that try to create the same directory
t1 = threading.Thread(target=create_dir, args=("A" * 260,)) # The name of the directory (must be shorter than 260 characters)
t2 = threading.Thread(target=create_dir, args=("A" * 260,))
t1.start()
t2.start()
t1.join()
t2.join()