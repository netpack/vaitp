import gradio as gr
import os

def process_text(text):
    if not isinstance(text, str):
        return "Invalid input: Input must be a string."
    
    sanitized_text = text.replace("<", "&lt;").replace(">", "&gt;")
    return sanitized_text

if __name__ == "__main__":
    demo = gr.Interface(
        fn=process_text, 
        inputs=gr.Textbox(label="Input Text"), 
        outputs=gr.Textbox(label="Output Text")
    )
    
    share_option = os.environ.get("GRADIO_SHARE", "False").lower() == "true"
    
    demo.launch(share=share_option)