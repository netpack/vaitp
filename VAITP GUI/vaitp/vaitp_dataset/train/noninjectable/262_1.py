# pal_chain/base.py (Vulnerable Version)

def dynamic_import(module_name):
    # Vulnerable to arbitrary code execution
    module = __import__(module_name)
    return module