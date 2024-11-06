# Mock function for incrementing a metric
def increment_metric(metric_name):
    print(f"Incrementing metric: {metric_name}")

def handle_request(request):
    # Unbounded cardinality metrics
    metric_name = request.method
    increment_metric(metric_name)

# Example request object
class Request:
    def __init__(self, method):
        self.method = method

# Simulate handling a request
request = Request("GET")
handle_request(request)