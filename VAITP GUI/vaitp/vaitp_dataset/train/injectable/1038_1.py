import gradio as gr

# Correctly setting enable_monitoring to False
interface = gr.Interface(fn=lambda x: x, inputs="text", outputs="text", enable_monitoring=False)

# Launching the interface
interface.launch()