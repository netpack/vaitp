import gradio as gr

# Vulnerable configuration allowing "null" as a valid origin
gr.Interface.localhost_aliases = ["localhost", "127.0.0.1", "null"]  # Includes "null"

# Example function to demonstrate Gradio interface
def greet(name):
    return f"Hello {name}!"

# Create the Gradio interface
iface = gr.Interface(fn=greet, inputs="text", outputs="text")

# Launch the Gradio server
iface.launch()