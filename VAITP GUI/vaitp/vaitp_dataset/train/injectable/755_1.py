import logging
from graphql import GraphQLError

# Set up logging
logging.basicConfig(level=logging.ERROR)

def handle_graphql_error(error):
    # Log the error details for internal use
    logging.error(f"GraphQL error occurred: {error}")

    # Return a generic error message to the user
    return {
        "errors": [
            {
                "message": "An internal error occurred. Please try again later."
            }
        ]
    }

def some_graphql_resolver():
    try:
        # Your logic here that might raise an exception
        raise ValueError("This is a sensitive error message that should not be exposed.")
    except Exception as e:
        # Handle the exception and prevent sensitive information leakage
        return handle_graphql_error(e)