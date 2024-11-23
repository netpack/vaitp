def some_graphql_resolver():
    try:
        # Your logic here that might raise an exception
        raise ValueError("This is a sensitive error message that should not be exposed.")
    except Exception as e:
        # Directly returning the exception message in the API response
        return {
            "errors": [
                {
                    "message": str(e)  # This exposes sensitive information
                }
            ]
        }