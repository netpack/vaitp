import gradio as gr
import threading

# Global variable to hold the root URL
root_url = "http://localhost:7860"

def update_root_in_config(new_root):
    global root_url
    # Simulate a race condition by allowing concurrent updates
    root_url = new_root

def attacker_thread():
    # Simulate an attacker trying to change the root URL
    for _ in range(10):
        update_root_in_config("http://malicious-server.com")

# Start the attacker thread
threading.Thread(target=attacker_thread).start()

# Simulate a legitimate update
update_root_in_config("http://my-secure-server.com")

# Print the final root URL to show potential exploitation
print("Final root URL:", root_url)