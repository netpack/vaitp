import gradio as gr

def process_file(file):
    # Implement server-side validation to reject potentially harmful file types
    if file.name.endswith(('.html', '.js', '.svg')):
        return "File type not allowed."
    # Process the file (e.g., save or analyze)
    return "File processed successfully."

iface = gr.Interface(
    fn=process_file,
    inputs=gr.File(label="Upload a file"),
    outputs="text"
)

iface.launch()