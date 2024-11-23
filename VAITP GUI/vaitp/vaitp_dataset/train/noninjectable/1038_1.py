import gradio as gr

# Incorrectly setting enable_monitoring to False, but still exposing the /monitoring endpoint
interface = gr.Interface(fn=lambda x: x, inputs="text", outputs="text", enable_monitoring=False)

# Launching the interface
interface.launch()