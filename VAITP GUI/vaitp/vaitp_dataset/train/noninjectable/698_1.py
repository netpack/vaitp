def execute_query(query, user):
    try:
        # Simulate query execution
        result = perform_query(query, user)
        return result
    except Exception as e:
        # Returning a generic error message to prevent exposing sensitive information
        return {"error": "An error occurred during query execution."}

def perform_query(query, user):
    # This function simulates the actual query execution logic
    # It may raise exceptions that could expose sensitive data
    if user.is_staff:
        # Simulating a potential exception that could expose sensitive data
        raise ValueError("Sensitive information: user@example.com")
    return {"data": "some_result"}