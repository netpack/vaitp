import gradio as gr

# A simple Gradio interface
def greet(name):
    return f"Hello, {name}!"

iface = gr.Interface(fn=greet, inputs="text", outputs="text")

# Launching the Gradio app without proper CORS validation
iface.launch()