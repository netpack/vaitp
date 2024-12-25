import gradio as gr
import os

def file_access(file_path):
    # Basic check to ensure the file path is within the allowed directory.
    # For a real application, you'd want a much more robust check.
    allowed_dir = "./"  # or specific directories to allow access to.
    normalized_path = os.path.normpath(file_path)
    if not normalized_path.startswith(allowed_dir):
        return "Error: File access not permitted"

    try:
        with open(normalized_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return "Error: File not found."
    except Exception as e:
        return f"Error: An unexpected error occurred: {e}"

# Gradio interface exposing the file access function
iface = gr.Interface(fn=file_access, inputs="text", outputs="text")
iface.launch()