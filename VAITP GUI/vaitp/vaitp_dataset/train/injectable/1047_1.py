import gradio as gr

# Modify the localhost_aliases to exclude "null" as a valid origin
gr.Interface.localhost_aliases = ["localhost", "127.0.0.1"]  # Exclude "null"

# Example function to demonstrate Gradio interface
def greet(name):
    return f"Hello {name}!"

# Create the Gradio interface
iface = gr.Interface(fn=greet, inputs="text", outputs="text")

# Launch the Gradio server
iface.launch()