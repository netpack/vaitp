import os

# Vulnerable code using eval()
def set_gpus():
    gpus = os.environ.get('PL_TRAINER_GPUS', '0')
    eval(f"gpus = [{gpus}]")  # This is vulnerable to code injection
    return gpus