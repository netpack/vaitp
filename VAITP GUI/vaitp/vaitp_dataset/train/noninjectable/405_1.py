import gradio as gr

def read_file(file_path):
    # Directly reading the file without any validation
    with open(file_path, 'r') as file:
        return file.read()

# Gradio interface that allows users to input a file path
iface = gr.Interface(fn=read_file, inputs="text", outputs="text")
iface.launch()