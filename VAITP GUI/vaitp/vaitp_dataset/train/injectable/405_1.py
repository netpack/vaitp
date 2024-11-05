import gradio as gr
import os

def read_file(file_path):
    # Define a base directory that is safe for file access
    base_directory = "/safe/directory/"
    
    # Normalize the input path to prevent directory traversal
    safe_path = os.path.abspath(os.path.join(base_directory, file_path))

    # Ensure the safe path is within the base directory
    if not safe_path.startswith(os.path.abspath(base_directory)):
        return "Access denied."

    try:
        # Attempt to open and read the file
        with open(safe_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return "File not found."

# Gradio interface that allows users to input a file path
iface = gr.Interface(fn=read_file, inputs="text", outputs="text")
iface.launch()