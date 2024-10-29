import gradio as gr
import os

def file_access(file_path):
    # Validate the file path to prevent unauthorized access
    safe_base_path = "/safe/directory/"
    full_path = os.path.join(safe_base_path, file_path)

    # Ensure the requested file is within the safe directory
    if not full_path.startswith(safe_base_path):
        return "Access Denied: Invalid file path."

    try:
        with open(full_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return "File not found."

# Gradio interface exposing the file access function
iface = gr.Interface(fn=file_access, inputs="text", outputs="text")
iface.launch()