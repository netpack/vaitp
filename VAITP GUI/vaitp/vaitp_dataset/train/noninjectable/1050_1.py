import gradio as gr

def process_file(file):
    # No validation on file type, allowing potentially harmful files
    return f"File {file.name} uploaded successfully."

iface = gr.Interface(
    fn=process_file,
    inputs=gr.File(label="Upload a file"),
    outputs="text"
)

iface.launch()