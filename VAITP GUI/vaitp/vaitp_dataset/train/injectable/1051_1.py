import gradio as gr
import re

def is_valid_url(url):
    # Allowlist for trusted domains
    allowlist = ["https://trusted-domain.com", "https://another-trusted.com"]
    return any(url.startswith(prefix) for prefix in allowlist)

def fetch_url(url):
    if not is_valid_url(url):
        raise ValueError("URL is not allowed.")
    # Proceed with fetching the URL
    return f"Fetched content from {url}"

iface = gr.Interface(fn=fetch_url, inputs="text", outputs="text")
iface.launch()