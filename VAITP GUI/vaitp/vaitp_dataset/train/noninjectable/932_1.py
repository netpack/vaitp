import gradio as gr
import os

def file_access(file_path):
    # Sanitize the file path to prevent traversal attacks
    base_dir = "./"  # Set a base directory
    sanitized_path = os.path.abspath(os.path.join(base_dir, file_path))

    # Check if the sanitized path is still within the base directory
    if not sanitized_path.startswith(os.path.abspath(base_dir)):
      return "Error: File path is outside the allowed directory."
    try:
      with open(sanitized_path, 'r') as file:
          return file.read()
    except FileNotFoundError:
      return "Error: File not found."
    except Exception as e:
        return f"Error reading file: {str(e)}"


iface = gr.Interface(fn=file_access, inputs="text", outputs="text")
iface.launch(share=True)