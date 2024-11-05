import os
import ast

# Patched code using ast.literal_eval()
def set_gpus():
    gpus = os.environ.get('PL_TRAINER_GPUS', '0')
    gpus = ast.literal_eval(f"[{gpus}]")  # This is secure against code injection
    return gpus