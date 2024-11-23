import gradio as gr

def vulnerable_function(user_input):
    # Directly using user input without validation
    with open(user_input['file_path'], 'r') as file:
        return file.read()

iface = gr.Interface(fn=vulnerable_function, inputs="json", outputs="text")
iface.launch()