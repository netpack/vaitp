# This code creates a directory with a long name that overflows the buffer
import os
import threading

def create_dir(name):
    os.makedirs(name, exist_ok=True) # This call triggers the race condition

# Create two threads that try to create the same directory
t1 = threading.Thread(target=create_dir, args=("A" * 260,)) # The name of the directory (must be longer than 259 characters)
t2 = threading.Thread(target=create_dir, args=("A" * 260,))
t1.start()
t2.start()
t1.join()
t2.join()