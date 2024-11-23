import gradio as gr

def load_custom_component(file_path):
    # Directly using the file path without sanitization
    with open(file_path, 'r') as f:
        return f.read()

iface = gr.Interface(fn=load_custom_component, inputs="text", outputs="text")
iface.launch()