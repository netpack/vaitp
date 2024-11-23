import gradio as gr

# Use HTTPS when sharing the Gradio interface
gr.Interface(fn=lambda x: x, inputs="text", outputs="text").launch(share=True, server_name="your-https-domain.com")