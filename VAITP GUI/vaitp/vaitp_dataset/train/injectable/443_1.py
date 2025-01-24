
import logging

# Mock function for incrementing a metric
def increment_metric(metric_name):
    logging.info(f"Incrementing metric: {metric_name}")

# Function to validate HTTP methods
def is_valid_method(method):
    # Define a set of valid HTTP methods
    valid_methods = {"GET", "POST", "PUT", "DELETE"}
    if method not in valid_methods:
        logging.warning(f"Invalid HTTP method: {method}")
        return False
    return True

def handle_request(request):
    # Limited cardinality metrics
    if is_valid_method(request.method):
        metric_name = request.method
        increment_metric(metric_name)

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