import os
import json
import re

# Function to validate and sanitize the uploaded weather data source
def validate_weather_data_source(data_source):
    # Allow only specific keys and types to prevent arbitrary code execution
    allowed_keys = {'name', 'url', 'api_key'}
    if not all(key in allowed_keys for key in data_source.keys()):
        raise ValueError("Invalid data source keys.")

    # Example of validating URL format
    url_pattern = re.compile(r'^(http|https)://[^\s/$.?#].[^\s]*$')
    if not url_pattern.match(data_source['url']):
        raise ValueError("Invalid URL format.")

    # Ensure no executable code is present in the input
    for key, value in data_source.items():
        if isinstance(value, str):
            if re.search(r'[\(\)\{\}\[\];]', value):
                raise ValueError("Invalid characters in input.")

    return True

# Function to handle the upload of a new weather data source
def add_new_weather_data_source(data_source_json):
    try:
        data_source = json.loads(data_source_json)
        if validate_weather_data_source(data_source):
            # Proceed with adding the validated data source
            print("Weather data source added successfully.")
            # Here you would add logic to save the data source
    except ValueError as e:
        print(f"Error: {e}")

# Example usage
data_source_json = '{"