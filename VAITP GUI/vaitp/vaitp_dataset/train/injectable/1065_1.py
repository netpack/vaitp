import gradio as gr
import json

def safe_function(user_input):
    # Validate and sanitize user input
    if not isinstance(user_input, dict):
        raise ValueError("Invalid input: Expected a JSON object.")
    
    # Further validation can be added here to ensure no harmful file paths are included

    # Process the input safely
    return "Processed input safely."

iface = gr.Interface(fn=safe_function, inputs="json", outputs="text")
iface.launch()