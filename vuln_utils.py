import logging
from utils import clear_memory

def llm_interpret_exploitation_result_etcpasswd(llm, exec_output):
    prompt = f"""<|im_start|>system<|im_sep|>
Does the following terminal output look like it contains the content of /etc/passwd?
Answer only with 'successful' if it does or 'not successful' if it does not, and nothing else.<|im_end|>
<|im_start|>user<|im_sep|>
{exec_output}
<|im_end|>
<|im_start|>assistant<|im_sep|>
"""
    clear_memory()
    response = llm(prompt, max_tokens=3, temperature=0.4, top_p=0.9, stream=False)
    text = response["choices"][0]["text"].strip().lower() if "choices" in response else ""
    return text

def llm_interpret_exploitation_result_open_redirect(llm, exec_output):
    prompt = f"""<|im_start|>system<|im_sep|>
Does the following HTTP response or server log output indicate an open redirection vulnerability (e.g. a 302 redirect with an unvalidated URL parameter)?
Answer only with 'successful' if it does or 'not successful' if it does not, and nothing else.<|im_end|>
<|im_start|>user<|im_sep|>
{exec_output}
<|im_end|>
<|im_start|>assistant<|im_sep|>
"""
    clear_memory()
    response = llm(prompt, max_tokens=3, temperature=0.4, top_p=0.9, stream=False)
    text = response["choices"][0]["text"].strip().lower() if "choices" in response else ""
    return text

def llm_interpret_exploitation_result_jinja2(llm, exec_output):
    prompt = f"""<|im_start|>system<|im_sep|>
Does the following HTTP response or server log output indicate a successful exploitation of a Jinja2 template injection (SSTI) vulnerability? 
Answer only with 'successful' if it does or 'not successful' if it does not, and nothing else.<|im_end|>
<|im_start|>user<|im_sep|>
{exec_output}
<|im_end|>
<|im_start|>assistant<|im_sep|>
"""
    clear_memory()
    response = llm(prompt, max_tokens=3, temperature=0.4, top_p=0.9, stream=False)
    text = response["choices"][0]["text"].strip().lower() if "choices" in response else ""
    return text

def llm_interpret_exploitation_result_pickle(llm, exec_output):
    prompt = f"""<|im_start|>system<|im_sep|>
Does the following terminal output indicate that a malicious pickle file was successfully deserialized and executed, triggering arbitrary code execution (for example, by executing 'head -n 30 /etc/passwd')?
Answer only with 'successful' if it does or 'not successful' if it does not, and nothing else.<|im_end|>
<|im_start|>user<|im_sep|>
{exec_output}
<|im_end|>
<|im_start|>assistant<|im_sep|>
"""
    clear_memory()
    response = llm(prompt, max_tokens=3, temperature=0.4, top_p=0.9, stream=False)
    text = response["choices"][0]["text"].strip().lower() if "choices" in response else ""
    return text

def llm_interpret_exploitation_result_ssrf(llm, exec_output):
    prompt = f"""<|im_start|>system<|im_sep|>
Does the following HTTP response or server log output indicate a successful exploitation of a Flask SSRF vulnerability, where the server fetched content from http://httpbin.org/get despite supposed domain restrictions (only allowing netpack.pt)?
Answer only with 'successful' if it does or 'not successful' if it does not, and nothing else.<|im_end|>
<|im_start|>user<|im_sep|>
{exec_output}
<|im_end|>
<|im_start|>assistant<|im_sep|>
"""
    clear_memory()
    response = llm(prompt, max_tokens=3, temperature=0.4, top_p=0.9, stream=False)
    text = response["choices"][0]["text"].strip().lower() if "choices" in response else ""
    return text
