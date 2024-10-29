from celery import Celery

app = Celery('tasks', broker='pyamqp://guest@localhost//')

@app.task
def example_task():
    return "This is a task."

# Simulating an attacker manipulating the backend
# The malicious data is still created, but the backend will not execute it
malicious_data = {
    'result': 'malicious_command',
    'exc_module': 'os',
    'exc_type': 'system',
    'exc_message': 'id'  # This could be a command to execute
}

# After the patch, this will raise an error or safely ignore the malicious command
try:
    result = app.backend.exception_to_python(malicious_data)
    print(result)  # This will not execute the 'id' command
except Exception as e:
    print("Caught an error:", e)  # Proper error handling