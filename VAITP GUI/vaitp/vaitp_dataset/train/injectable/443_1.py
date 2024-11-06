# Mock function for incrementing a metric
def increment_metric(metric_name):
    print(f"Incrementing metric: {metric_name}")

# Function to validate HTTP methods
def is_valid_method(method):
    # Define a set of valid HTTP methods
    valid_methods = {"GET", "POST", "PUT", "DELETE"}
    return method in valid_methods

def handle_request(request):
    # Limited cardinality metrics
    if is_valid_method(request.method):
        metric_name = request.method
        increment_metric(metric_name)
    else:
        log_invalid_method(request.method)

def log_invalid_method(method):
    print(f"Invalid HTTP method: {method}")

# Example request object
class Request:
    def __init__(self, method):
        self.method = method

# Simulate handling a valid request
valid_request = Request("GET")
handle_request(valid_request)

# Simulate handling an invalid request
invalid_request = Request("PATCH")
handle_request(invalid_request)