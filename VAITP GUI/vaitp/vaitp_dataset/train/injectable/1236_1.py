import os
import hashlib
import requests

CACHE_DIR = ".check-jsonschema-cache"

def get_schema(schema_url):
    # Generate a unique filename based on the URL hash
    filename = hashlib.sha256(schema_url.encode()).hexdigest() + ".json"
    cache_path = os.path.join(CACHE_DIR, filename)

    if os.path.exists(cache_path):
        with open(cache_path, "r") as f:
            return f.read()
    else:
        os.makedirs(CACHE_DIR, exist_ok=True)
        response = requests.get(schema_url)
        response.raise_for_status()
        with open(cache_path, "w") as f:
            f.write(response.text)
        return response.text

# Example usage (improved)
schema_data = get_schema("https://example.org/schema.json")
print(schema_data)