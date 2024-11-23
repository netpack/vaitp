def format_columns(columns):
    # No limit on the number of columns, which can lead to excessive memory consumption
    formatted_columns = [str(column) for column in columns]
    return formatted_columns