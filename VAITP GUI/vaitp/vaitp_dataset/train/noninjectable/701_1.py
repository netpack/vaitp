import pickle

# Example of a task that uses pickle (vulnerable code)
task_data = {
    'model': 'my_model',
    'data': [1, 2, 3, 4, 5]
}

# Vulnerable serialization using pickle
serialized_data = pickle.dumps(task_data)

# Now, you can send serialized_data (vulnerable to code execution)
print(serialized_data)