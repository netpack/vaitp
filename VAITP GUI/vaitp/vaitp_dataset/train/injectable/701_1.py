import json

# Example of a task that would have used pickle (vulnerable code)
# import pickle

# Task data that needs to be serialized
task_data = {
    'model': 'my_model',
    'data': [1, 2, 3, 4, 5]
}

# Fix: Use JSON serialization instead of pickle
serialized_data = json.dumps(task_data)

# Now, you can send serialized_data safely
print(serialized_data)