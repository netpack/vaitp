import gradio as gr

def secure_update_root_in_config(new_root):
    # Ensure that the root URL is updated safely without race conditions
    # This is a simplified example to demonstrate the concept
    # In practice, proper locking mechanisms or atomic operations would be used
    global current_root
    current_root = new_root

current_root = "http://localhost:7860"  # Default root URL

# Example of how to safely update the root URL
secure_update_root_in_config("http://my-secure-server.com")