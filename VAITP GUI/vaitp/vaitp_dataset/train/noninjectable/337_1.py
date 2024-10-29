import gradio as gr

def file_access(file_path):
    # Directly serving files without proper validation
    with open(file_path, 'r') as file:
        return file.read()

# Gradio interface exposing the file access function
iface = gr.Interface(fn=file_access, inputs="text", outputs="text")
iface.launch()