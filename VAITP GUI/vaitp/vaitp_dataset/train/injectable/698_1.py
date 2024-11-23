from graphql import GraphQLError

def execute_query(query, user):
    try:
        # Simulate query execution
        result = perform_query(query, user)
        return result
    except Exception as e:
        # Log the error internally without exposing sensitive information
        log_error(e)
        # Return a generic error message to the API consumer
        raise GraphQLError("An internal error occurred. Please try again later.")

def perform_query(query, user):
    # This function simulates the actual query execution logic
    # It may raise exceptions that need to be handled
    if user.is_staff:
        # Simulating a potential exception that could expose sensitive data
        raise ValueError("Sensitive information: user@example.com")
    return {"data": "some_result"}