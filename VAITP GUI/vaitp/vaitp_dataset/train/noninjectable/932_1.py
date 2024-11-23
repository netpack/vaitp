import gradio as gr

def file_access(file_path):
    # Vulnerable to file traversal attacks
    with open(file_path, 'r') as file:
        return file.read()

iface = gr.Interface(fn=file_access, inputs="text", outputs="text")
iface.launch(share=True)