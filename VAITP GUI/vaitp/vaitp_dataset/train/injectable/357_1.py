import os
import gradio as gr

# Retrieve SSH key from environment variable (patched code)
ssh_key = os.getenv("SSH_PRIVATE_KEY")

def launch_app():
    # Launch the Gradio app with sharing enabled
    gr.Interface(fn=my_function, inputs="text", outputs="text").launch(share=True)

# Function that uses the SSH key
def my_function(input_text):
    if ssh_key is None:
        return "SSH key not found. Please set the SSH_PRIVATE_KEY environment variable."
    return f"Using SSH key: {ssh_key}"

if __name__ == "__main__":
    launch_app()