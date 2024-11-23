def safe_format_columns(columns):
    # Limit the maximum size of columns to prevent excessive memory consumption
    MAX_COLUMNS = 100  # Set a safe limit for columns
    if len(columns) > MAX_COLUMNS:
        raise ValueError("Too many columns provided, limit is {}".format(MAX_COLUMNS))
    
    # Proceed with formatting columns safely
    formatted_columns = [str(column) for column in columns]
    return formatted_columns