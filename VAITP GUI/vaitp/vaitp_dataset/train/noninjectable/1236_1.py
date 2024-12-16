import os
import hashlib
import requests
from jsonschema import validate

CACHE_DIR = ".check-jsonschema-cache"

def get_schema(schema_url):
    """Fetches a schema from a URL, caching it if possible."""
    os.makedirs(CACHE_DIR, exist_ok=True)  # Create cache directory if it doesn't exist

    # Vulnerable part: uses only basename for cache key
    cache_filename = os.path.join(CACHE_DIR, os.path.basename(schema_url))

    if os.path.exists(cache_filename):
        with open(cache_filename, "r") as f:
            schema = f.read()
    else:
        response = requests.get(schema_url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        schema = response.text
        with open(cache_filename, "w") as f:
            f.write(schema)

    return schema


def validate_json(json_data, schema_url):
    """Validates JSON data against a schema from a URL."""
    schema = get_schema(schema_url)
    try:
      import json
      schema_data = json.loads(schema) #Added to ensure schema is valid json
      validate(instance=json_data, schema=schema_data)
      return True
    except Exception as e:
      return False


# Example usage (vulnerable):
malicious_schema_url = "https://example.evil.org/schema.json"  # Attacker-controlled schema
benign_schema_url = "https://example.org/schema.json"       # Legitimate schema

#Attacker uploads malicious schema to example.evil.org with the filename "schema.json"
# A subsequent call with the legitimate URL will load the malicious schema due to cache collision

json_data = {"a": 1} #Example JSON Data

#This will likely fail if a legitimate schema is at benign_schema_url and a malicious one is at malicious_schema_url. 
#The vulnerability is that the attacker can cause the malicious schema to be cached and used.
validation_result = validate_json(json_data, benign_schema_url)  
print(f"Validation result: {validation_result}")