import gradio as gr

def vulnerable_download(file_path):
    # This function does not validate the file path, allowing arbitrary access
    return file_path

iface = gr.Interface(fn=vulnerable_download, inputs="text", outputs="file")
iface.launch()