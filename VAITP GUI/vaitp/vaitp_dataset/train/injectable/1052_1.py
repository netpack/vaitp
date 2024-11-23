import gradio as gr

def secure_download(file_path):
    # Ensure the file path is within a safe directory
    safe_directory = "/safe/directory/"
    if not file_path.startswith(safe_directory):
        raise ValueError("Unauthorized file access attempt.")
    
    # Proceed to return the file if it's within the safe directory
    return file_path

iface = gr.Interface(fn=secure_download, inputs="text", outputs="file")
iface.launch()