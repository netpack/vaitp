import gradio as gr

# Insecure usage of share=True without HTTPS
gr.Interface(fn=lambda x: x, inputs="text", outputs="text").launch(share=True)