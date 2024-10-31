import gradio as gr

# Hard-coded SSH key (vulnerable code)
ssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"

def launch_app():
    # Launch the Gradio app with sharing enabled
    gr.Interface(fn=my_function, inputs="text", outputs="text").launch(share=True)

# Function that uses the SSH key
def my_function(input_text):
    # Use the SSH key for some operation
    return f"Using SSH key: {ssh_key}"

if __name__ == "__main__":
    launch_app()